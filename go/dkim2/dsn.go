package dkim2

import (
	"bytes"
	"crypto"
	"fmt"
	"regexp"
	"sort"
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

// dsnReport is a parsed RFC 6522 multipart/report: the DSN's own headers, and
// its body split into MIME segments with the returned-original part located.
type dsnReport struct {
	headers     []Header
	delim       string   // the boundary delimiter the segments were split on
	segments    []string // body split on delim; [0] is the preamble
	embeddedSeg int      // index in segments of the returned original
	headersOnly bool     // the returned original is text/rfc822-headers
}

// parseReport parses a raw DSN and validates its RFC 6522 structure: a
// multipart/report with (at least) three component parts — a human-readable
// text part first, a message/delivery-status part, and a part carrying the
// returned message (message/rfc822 or, if only headers are echoed back,
// text/rfc822-headers). A bare part count is not enough: a report with two
// text/plain parts and an embedded original would pass a ">= 3" check without
// being a valid DSN.
func parseReport(raw []byte) (*dsnReport, error) {
	headers, bodyReader, err := parseHeaders(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("parsing DSN headers: %w", err)
	}
	body := new(bytes.Buffer)
	if _, err := body.ReadFrom(bodyReader); err != nil {
		return nil, err
	}

	var ct string
	for _, h := range headers {
		if strings.EqualFold(h.Name, "content-type") {
			ct = h.Raw
		}
	}
	if !strings.Contains(strings.ToLower(ct), "multipart/report") {
		return nil, fmt.Errorf("not a multipart/report DSN")
	}
	m := reBoundary.FindStringSubmatch(ct)
	if m == nil {
		return nil, fmt.Errorf("no MIME boundary in Content-Type")
	}

	// Split the body into MIME parts on the boundary delimiter.
	// segments[0] is the preamble; the last is the closing "--\r\n" epilogue.
	delim := "--" + m[1]
	segments := strings.Split(body.String(), delim)

	hasTextPart := false
	hasDeliveryStatus := false
	embeddedSeg := -1
	headersOnly := false
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
			headersOnly = strings.Contains(lhdr, "text/rfc822-headers")
		}
	}
	if !hasTextPart {
		return nil, fmt.Errorf("DSN first part is not human-readable text/plain (RFC 6522)")
	}
	if !hasDeliveryStatus {
		return nil, fmt.Errorf("DSN missing message/delivery-status part (RFC 6522)")
	}
	if embeddedSeg < 0 {
		return nil, fmt.Errorf("no embedded original message part")
	}

	return &dsnReport{
		headers:     headers,
		delim:       delim,
		segments:    segments,
		embeddedSeg: embeddedSeg,
		headersOnly: headersOnly,
	}, nil
}

// AuthResult is what Authenticate found out about an inbound DSN.
type AuthResult struct {
	OK          bool            // the returned original's chain verified
	Reason      error           // why it did not, when OK is false
	Top         *DKIM2Signature // highest-i signature of the returned original, nil if unsigned
	HeadersOnly bool            // the DSN carried header fields only
	Embedded    []byte          // the returned original as it arrived
	Results     []VerifyResult  // per-signature detail from Verify
}

// Authenticate authenticates an inbound DSN before it is propagated (spec-06
// §12.1.2): the returned original's DKIM2 chain must verify, from its header
// fields alone when the DSN carries only headers. Deciding whether Top is a
// signature the caller itself made (d= and mf=, §12.1.2 point 2) is left to
// the caller, since only it knows its own domains.
//
// The returned error means this is not an RFC 6522 DSN at all (as for
// Propagate); a DSN that simply fails to authenticate comes back with
// OK false and Reason set.
func Authenticate(raw []byte, fetcher KeyFetcher, opts ...VerifyOptions) (*AuthResult, error) {
	rep, err := parseReport(raw)
	if err != nil {
		return nil, err
	}
	_, partBody := splitPartHeaders(rep.segments[rep.embeddedSeg])
	embedded := []byte(partBody)

	res := &AuthResult{HeadersOnly: rep.headersOnly, Embedded: embedded}
	if top, terr := topSig(embedded); terr == nil {
		res.Top = top
	}

	vopts := VerifyOptions{}
	if len(opts) > 0 {
		vopts = opts[0]
	}
	vopts.HeadersOnly = rep.headersOnly

	results, verr := Verify(bytes.NewReader(embedded), fetcher, vopts)
	res.Results = results
	if verr != nil {
		res.Reason = verr
		return res, nil
	}
	if len(results) == 0 {
		res.Reason = fmt.Errorf("no DKIM2-Signature headers found")
		return res, nil
	}
	for _, r := range results {
		if r.Error != nil {
			res.Reason = r.Error
			return res, nil
		}
	}
	res.OK = true
	return res, nil
}

// Propagate returns a DKIM2 DSN propagated upstream (RFC 6522 / draft-06
// §12.1.1): the Forwarder rebuilds the enclosed original to its
// forwarded-outward state (undoing its Message-Instance modification, which
// also drops the DKIM2-Signature it added), then re-signs the whole DSN as a
// new message (MAIL FROM <>, one Message-Instance, one DKIM2-Signature).
// Returns the propagated DSN bytes and the upstream MAIL FROM it should be
// sent to.
func Propagate(raw []byte, opts PropagateOptions) ([]byte, string, error) {
	rep, err := parseReport(raw)
	if err != nil {
		return nil, "", err
	}
	headers, delim, segments := rep.headers, rep.delim, rep.segments

	partHdr, partBody := splitPartHeaders(segments[rep.embeddedSeg])
	embedded := []byte(partBody)

	// 1. Undo the Forwarder's outward modification, so what remains is the
	//    message as the upstream hop signed it.
	//
	//    The target is the upstream signature's m=, NOT simply "highest MI - 1":
	//    a forwarder that changed nothing adds no Message-Instance at all and
	//    reuses the existing m= (§9.1/§9.2.5), so both signatures share one
	//    instance and there is no MI to unwind — unwinding by version anyway
	//    would strip the upstream's own signature along with the forwarder's.
	//    In that case we only drop the forwarder's signature.
	target, haveTarget := upstreamSigMIVersion(embedded)

	var rebuilt bytes.Buffer
	undone := false
	if haveTarget {
		if err := Undo(bytes.NewReader(embedded), &rebuilt, target); err == nil {
			undone = true
		}
	}
	if !undone {
		// Nothing to unwind (or unrecoverable) — strip the Forwarder's signature.
		stripped, serr := stripTopSig(embedded)
		if serr != nil {
			return nil, "", fmt.Errorf("rebuild embedded original: %v", serr)
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
	//    splitPartHeaders strips the blank line that ends the part's own header
	//    block, so both CRLFs have to go back: one to end the last part header,
	//    one for the separator. With only one, the returned message's headers
	//    are absorbed into the part's header block and it has no body at all.
	segments[rep.embeddedSeg] = partHdr + "\r\n\r\n" + string(embeddedFinal)
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
// upstreamSigMIVersion returns the m= of the second-highest DKIM2-Signature —
// the instance the upstream hop signed against, and therefore the state we want
// to reconstruct by undoing the top (Forwarder) hop. Reports false when there
// is no second signature to fall back to.
func upstreamSigMIVersion(raw []byte) (int, bool) {
	headers, _, err := parseHeaders(bytes.NewReader(raw))
	if err != nil {
		return 0, false
	}
	var sigs []*DKIM2Signature
	for _, h := range headers {
		if strings.EqualFold(h.Name, "dkim2-signature") {
			if sig, err := parseSig(h.Raw); err == nil {
				sigs = append(sigs, sig)
			}
		}
	}
	if len(sigs) < 2 {
		return 0, false
	}
	sort.Slice(sigs, func(i, j int) bool { return sigs[i].Sequence < sigs[j].Sequence })
	return sigs[len(sigs)-2].MIVersion, true
}

func stripTopSig(raw []byte) ([]byte, error) {
	headers, bodyReader, err := parseHeaders(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	body := new(bytes.Buffer)
	body.ReadFrom(bodyReader)

	// Collect the sequence numbers present, then decide which to drop: the
	// highest, and then any nd= signature left on top, since a §9.3 bridge
	// belongs to the hop it was made for and an nd= signature is never valid
	// as the top of a chain.
	bySeq := map[int]*DKIM2Signature{}
	var seqs []int
	for _, h := range headers {
		if strings.EqualFold(h.Name, "dkim2-signature") {
			if sig, err := parseSig(h.Raw); err == nil {
				bySeq[sig.Sequence] = sig
				seqs = append(seqs, sig.Sequence)
			}
		}
	}
	if len(seqs) == 0 {
		return nil, fmt.Errorf("no DKIM2-Signature to strip")
	}
	sort.Ints(seqs)
	drop := map[int]bool{seqs[len(seqs)-1]: true}
	for i := len(seqs) - 2; i >= 0; i-- {
		if bySeq[seqs[i]].NextDomain == "" {
			break
		}
		drop[seqs[i]] = true
	}

	var out bytes.Buffer
	for _, h := range headers {
		if strings.EqualFold(h.Name, "dkim2-signature") {
			if sig, err := parseSig(h.Raw); err == nil && drop[sig.Sequence] {
				continue
			}
		}
		out.WriteString(h.Raw)
	}
	out.WriteString("\r\n")
	out.Write(body.Bytes())
	return out.Bytes(), nil
}

// topSig returns the highest-sequence DKIM2-Signature of a raw message.
func topSig(raw []byte) (*DKIM2Signature, error) {
	headers, _, err := parseHeaders(bytes.NewReader(raw))
	if err != nil {
		return nil, err
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
		return nil, fmt.Errorf("no DKIM2-Signature found")
	}
	return top, nil
}

// topSigMailFrom returns the MAIL FROM of the highest-sequence DKIM2-Signature.
func topSigMailFrom(raw []byte) (string, error) {
	top, err := topSig(raw)
	if err != nil {
		return "", fmt.Errorf("no DKIM2-Signature to derive upstream MAIL FROM")
	}
	return top.MailFrom, nil
}
