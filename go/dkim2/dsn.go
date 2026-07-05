package dkim2

import (
	"bytes"
	"crypto"
	"fmt"
	"regexp"
	"strings"
)

// PropagateOptions carries the signing parameters for the propagated DSN.
type PropagateOptions struct {
	ForwarderDomain string // the Forwarder's own domain (informational)
	Key             crypto.PrivateKey
	Selector        string
	Domain          string
	Timestamp       int64
}

var reBoundary = regexp.MustCompile(`(?i)boundary="?([^";]+)"?`)

// Propagate returns a DKIM2 DSN propagated upstream (RFC 3462 / draft-04
// §12.1.1): the Forwarder rebuilds the enclosed original to its
// forwarded-outward state (undoing its Message-Instance modification, which
// also drops the DKIM2-Signature it added), then re-signs the whole DSN as a
// new message (MAIL FROM <>, one Message-Instance, one DKIM2-Signature).
// Returns the propagated DSN bytes and the upstream MAIL FROM it should be
// sent to.
func Propagate(raw []byte, opts PropagateOptions) ([]byte, string, error) {
	headers, bodyReader, err := parseHeaders(bytes.NewReader(raw))
	if err != nil {
		return nil, "", fmt.Errorf("parsing DSN headers: %w", err)
	}
	body := new(bytes.Buffer)
	if _, err := body.ReadFrom(bodyReader); err != nil {
		return nil, "", err
	}

	var ct string
	for _, h := range headers {
		if strings.EqualFold(h.Name, "content-type") {
			ct = h.Raw
		}
	}
	if !strings.Contains(strings.ToLower(ct), "multipart/report") {
		return nil, "", fmt.Errorf("not a multipart/report DSN")
	}
	m := reBoundary.FindStringSubmatch(ct)
	if m == nil {
		return nil, "", fmt.Errorf("no MIME boundary in Content-Type")
	}
	boundary := m[1]

	// Split the body into MIME parts on the boundary delimiter.
	delim := "--" + boundary
	segments := strings.Split(body.String(), delim)
	// segments[0] is the preamble; the last is the closing "--\r\n" epilogue.
	//
	// RFC 3462 requires a multipart/report DSN to have (at least) three
	// component parts: a human-readable text part first, a
	// message/delivery-status part, and a part carrying the returned
	// message (message/rfc822 or, if only headers are echoed back,
	// text/rfc822-headers). Validate all three are present before trusting
	// the structure enough to rebuild and re-sign it.
	hasTextPart := false
	hasDeliveryStatus := false
	embeddedSeg := -1
	for i := 1; i < len(segments)-1; i++ {
		hdr, _ := splitPartHeaders(segments[i])
		lhdr := strings.ToLower(hdr)
		if i == 1 && strings.Contains(lhdr, "text/plain") {
			hasTextPart = true
		}
		if strings.Contains(lhdr, "message/delivery-status") {
			hasDeliveryStatus = true
		}
		if embeddedSeg < 0 && (strings.Contains(lhdr, "message/rfc822") ||
			strings.Contains(lhdr, "text/rfc822-headers")) {
			embeddedSeg = i
		}
	}
	if !hasTextPart {
		return nil, "", fmt.Errorf("DSN first part is not human-readable text/plain (RFC 3462)")
	}
	if !hasDeliveryStatus {
		return nil, "", fmt.Errorf("DSN missing message/delivery-status part (RFC 3462)")
	}
	if embeddedSeg < 0 {
		return nil, "", fmt.Errorf("no embedded original message part")
	}

	partHdr, partBody := splitPartHeaders(segments[embeddedSeg])
	embedded := []byte(partBody)

	// 1. Undo the Forwarder's outward modification. Undo also drops the
	//    DKIM2-Signature whose m= covers the removed MI. If there is nothing to
	//    undo (single MI), strip the top signature directly.
	var rebuilt bytes.Buffer
	if err := Undo(bytes.NewReader(embedded), &rebuilt, -1); err != nil {
		// No MI to undo (or unrecoverable) — strip the Forwarder's signature.
		stripped, serr := stripTopSig(embedded)
		if serr != nil {
			return nil, "", fmt.Errorf("rebuild embedded original: %v / %v", err, serr)
		}
		rebuilt.Reset()
		rebuilt.Write(stripped)
	}
	embeddedFinal := rebuilt.Bytes()

	// 2. Upstream = MAIL FROM of the now-highest DKIM2-Signature.
	upstream, err := topSigMailFrom(embeddedFinal)
	if err != nil {
		return nil, "", err
	}

	// 3. Splice the rebuilt original back into the part and reassemble the body.
	segments[embeddedSeg] = partHdr + "\r\n" + string(embeddedFinal)
	newBody := strings.Join(segments, delim)

	// 4. Reassemble the DSN (unchanged outer headers + new body) and re-sign it
	//    as a NEW message with MAIL FROM <>.
	var assembled bytes.Buffer
	for _, h := range headers {
		assembled.WriteString(h.Raw)
	}
	assembled.WriteString("\r\n")
	assembled.WriteString(newBody)

	var signed bytes.Buffer
	if err := Sign(bytes.NewReader(assembled.Bytes()), &signed, opts.Key, SignOptions{
		Selector: opts.Selector, Domain: opts.Domain,
		MailFrom: "<>", RcptTo: []string{upstream}, Timestamp: opts.Timestamp,
	}); err != nil {
		return nil, "", fmt.Errorf("re-signing propagated DSN: %w", err)
	}
	return signed.Bytes(), upstream, nil
}

// splitPartHeaders splits a MIME part segment into its header block and body
// (on the first blank line). Leading CRLF after the boundary is trimmed.
func splitPartHeaders(seg string) (string, string) {
	seg = strings.TrimPrefix(seg, "\r\n")
	if idx := strings.Index(seg, "\r\n\r\n"); idx >= 0 {
		return seg[:idx], seg[idx+4:]
	}
	return seg, ""
}

// stripTopSig removes the highest-sequence DKIM2-Signature header from a raw
// message (used when there is no Message-Instance to undo).
func stripTopSig(raw []byte) ([]byte, error) {
	headers, bodyReader, err := parseHeaders(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	body := new(bytes.Buffer)
	body.ReadFrom(bodyReader)

	maxSeq, found := -1, false
	for _, h := range headers {
		if strings.EqualFold(h.Name, "dkim2-signature") {
			if sig, err := parseSig(h.Raw); err == nil && sig.Sequence > maxSeq {
				maxSeq, found = sig.Sequence, true
			}
		}
	}
	if !found {
		return nil, fmt.Errorf("no DKIM2-Signature to strip")
	}
	var out bytes.Buffer
	for _, h := range headers {
		if strings.EqualFold(h.Name, "dkim2-signature") {
			if sig, err := parseSig(h.Raw); err == nil && sig.Sequence == maxSeq {
				continue
			}
		}
		out.WriteString(h.Raw)
	}
	out.WriteString("\r\n")
	out.Write(body.Bytes())
	return out.Bytes(), nil
}

// topSigMailFrom returns the MAIL FROM of the highest-sequence DKIM2-Signature.
func topSigMailFrom(raw []byte) (string, error) {
	headers, _, err := parseHeaders(bytes.NewReader(raw))
	if err != nil {
		return "", err
	}
	var top *DKIM2Signature
	for _, h := range headers {
		if strings.EqualFold(h.Name, "dkim2-signature") {
			if sig, err := parseSig(h.Raw); err == nil {
				if top == nil || sig.Sequence > top.Sequence {
					top = sig
				}
			}
		}
	}
	if top == nil {
		return "", fmt.Errorf("no DKIM2-Signature to derive upstream MAIL FROM")
	}
	return top.MailFrom, nil
}
