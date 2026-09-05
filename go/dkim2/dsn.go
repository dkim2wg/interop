package dkim2

import (
	"bytes"
	"crypto"
	"errors"
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

	// Fetcher authenticates the inbound DSN (§12.1.2) before it is
	// propagated. Required unless SkipAuthentication is set.
	Fetcher KeyFetcher
	// SkipAuthentication propagates without the §12.1.2 check, for a caller
	// that has authenticated already (or is exercising the rebuild machinery
	// on a fixture, as dsn_test.go does).
	SkipAuthentication bool
	// SkipTimestampCheck is passed through to the authentication verify.
	SkipTimestampCheck bool
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
	OK          bool            // every §12.1.2 check that could run did pass
	Reason      error           // why it did not, when OK is false
	Top         *DKIM2Signature // highest-i signature of the returned original, nil if unsigned
	DSNSig      *DKIM2Signature // the DSN's own originating (i=1) signature, nil if unsigned
	DSNError    error           // why the DSN's own chain did not verify, if it did not
	Alignment   string          // §12.1.2 point 1: "pass", "fail" or "none"
	AlignDetail string          // what that alignment decision was based on
	HeadersOnly bool            // the DSN carried header fields only
	Embedded    []byte          // the returned original as it arrived
	Results     []VerifyResult  // per-signature detail from Verify
}

// checkAlignment applies spec-06 §12.1.2 point 1: "The DSN's DKIM2-Signature
// will have a signing domain that is aligned with the recipient of the message
// that is being returned. The recipient's address is located in the rt= tag of
// the last (highest i= tag) DKIM2-Signature in the returned message."
//
// This is the check that says the bounce came from the place we handed the
// message to, and it is worth nothing unless the DSN's own signature has been
// verified — anyone can write d=. Authenticate therefore verifies the DSN as
// well, and only compares the d= it has proved.
//
// The direction is §9.4's: labels come off the left of the ADDRESS domain, so
// d= may be equal to or a parent of the rt= domain, never a child of it. A
// system with a dedicated bounce domain signs as its organizational domain
// (d=example.com) and puts the bounce address on the subdomain
// (<...@bounces.example.com>) — the subdomain belongs in the address, not in
// the signing domain — so nothing legitimate needs the other direction.
func checkAlignment(dsnSig, origTop *DKIM2Signature) (string, string) {
	if dsnSig == nil {
		return "none", "DSN carries no DKIM2-Signature of its own"
	}
	d := strings.ToLower(dsnSig.Domain)
	if d == "" {
		return "none", "DSN signature has no d="
	}
	if origTop == nil || len(origTop.RcptTo) == 0 {
		return "none", "returned message's top signature has no rt= to align with"
	}
	for _, r := range origTop.RcptTo {
		rd := domainFromAddr(r)
		if rd == "" {
			continue
		}
		if relaxedDomainMatch(rd, d) {
			return "pass", fmt.Sprintf("DSN d=%s is aligned with rt= %s", d, r)
		}
	}
	return "fail", fmt.Sprintf("DSN d=%s is not aligned with the returned message's rt= (%s)",
		d, strings.Join(origTop.RcptTo, ", "))
}

// Authenticate authenticates an inbound DSN before it is propagated (spec-06
// §12.1.2):
//
//   - the returned original's DKIM2 chain must verify, from its header fields
//     alone when the DSN carries only headers (point 3);
//   - the DSN's own signature must verify, and its d= must be aligned with the
//     rt= of the returned original's top signature — i.e. the bounce came from
//     the system the message was handed to (point 1);
//   - deciding whether Top is a signature the caller itself made (d= and mf=)
//     is left to the caller (point 2), since only it knows its own domains.
//
// A DSN carrying no DKIM2-Signature at all is not what §12.1.2 is about ("When
// a system receives a DKIM2 signed DSN"), so it comes back with DSNSig nil and
// Alignment "none" rather than failed.
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

	// The DSN itself, from the bytes as they arrived.
	dsnOpts := vopts
	dsnOpts.HeadersOnly = false
	dsnSigned := false
	if sig, serr := originSig(raw); serr == nil {
		res.DSNSig = sig
		dsnSigned = true
	}
	if dsnSigned {
		dsnResults, dverr := Verify(bytes.NewReader(raw), fetcher, dsnOpts)
		res.DSNError = dverr
		if dverr == nil {
			for _, r := range dsnResults {
				if r.Error != nil {
					res.DSNError = r.Error
					break
				}
			}
		}
	}

	switch {
	case !dsnSigned:
		res.Alignment, res.AlignDetail = "none", "DSN carries no DKIM2-Signature of its own"
	case res.DSNError != nil:
		res.Alignment, res.AlignDetail = "none", "DSN's own signature did not verify"
	default:
		res.Alignment, res.AlignDetail = checkAlignment(res.DSNSig, res.Top)
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
	if res.DSNError != nil {
		res.Reason = fmt.Errorf("DSN's own signature did not verify: %w", res.DSNError)
		return res, nil
	}
	if res.Alignment == "fail" {
		res.Reason = fmt.Errorf("%s", res.AlignDetail)
		return res, nil
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
//
// §12.1.2 is not optional here: "If the verification fails then the DSN MUST
// NOT be propagated any further", so the DSN is authenticated first and an
// error returned rather than re-signing one that could not be authenticated.
// That needs opts.Fetcher, unless opts.SkipAuthentication says the caller has
// done it already.
func Propagate(raw []byte, opts PropagateOptions) ([]byte, string, error) {
	if !opts.SkipAuthentication {
		if opts.Fetcher == nil {
			return nil, "", fmt.Errorf("propagate: need a Fetcher to authenticate the DSN " +
				"(§12.1.2), or SkipAuthentication if it has been authenticated already")
		}
		auth, aerr := Authenticate(raw, opts.Fetcher,
			VerifyOptions{SkipTimestampCheck: opts.SkipTimestampCheck})
		if aerr != nil {
			return nil, "", aerr
		}
		if !auth.OK {
			return nil, "", fmt.Errorf(
				"propagate: DSN did not authenticate (§12.1.2), not propagating: %w", auth.Reason)
		}
	}

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

	embeddedFinal := embedded
	headersOnly := rep.headersOnly
	undone := false
	// Only unwind when there is actually an instance above the target. A
	// forwarder that changed nothing reuses the upstream's m=, so the two are
	// equal and there is nothing to undo — that is the ordinary case below,
	// not a failure, and it must not be reached through Undo's error path.
	topV, haveTopV := topMIVersion(embedded)
	if haveTarget && haveTopV && topV > target {
		var rebuilt bytes.Buffer
		err := Undo(bytes.NewReader(embedded), &rebuilt, target)
		switch {
		case err == nil:
			embeddedFinal = rebuilt.Bytes()
			undone = true
		case errors.Is(err, ErrUnrecoverable):
			// §12.1.1: the upstream declared the previous body unrecoverable,
			// so the returned original goes back as header fields only. Our
			// own instance goes with our hop — leaving it would put an
			// instance above the top remaining signature (§11 "is not
			// signed") for whoever receives this.
			headersOnly = true
			stripped, serr := stripTopMI(embedded)
			if serr != nil {
				return nil, "", fmt.Errorf("rebuild embedded original: %w", serr)
			}
			embeddedFinal = stripped
		default:
			// Any OTHER reconstruction failure means we cannot rebuild what we
			// forwarded, so there is nothing truthful to return. Swallowing it
			// here (as this did) shipped a returned message whose body does
			// not match the signature above it.
			return nil, "", fmt.Errorf("rebuild embedded original: %w", err)
		}
	}
	if !undone {
		// Nothing to unwind, or the body was declared unrecoverable — either
		// way the Forwarder's own signature comes off by hand.
		stripped, serr := stripTopSig(embeddedFinal)
		if serr != nil {
			return nil, "", fmt.Errorf("rebuild embedded original: %v", serr)
		}
		embeddedFinal = stripped
	}

	// 2. Upstream = MAIL FROM of the now-highest DKIM2-Signature.
	upstream, err := topSigMailFrom(embeddedFinal)
	if err != nil {
		return nil, "", err
	}

	// 3. Splice the rebuilt original back into the part and reassemble the body.
	//    splitPartHeaders trims the CRLF that ends the boundary DELIMITER line
	//    as well as the blank line that ends the part's own header block, so
	//    all three CRLFs have to go back: without the leading one the part
	//    headers are glued onto the "--boundary" line and no MIME parser sees
	//    a part at all, and with only one of the other two the returned
	//    message's headers are absorbed into the part's header block.
	if headersOnly {
		hdrs, _, herr := parseHeaders(bytes.NewReader(embeddedFinal))
		if herr != nil {
			return nil, "", fmt.Errorf("reading returned message headers: %w", herr)
		}
		var hb bytes.Buffer
		for _, h := range hdrs {
			hb.WriteString(h.Raw)
		}
		segments[rep.embeddedSeg] = "\r\nContent-Type: text/rfc822-headers\r\n\r\n" + hb.String()
	} else {
		segments[rep.embeddedSeg] = "\r\n" + partHdr + "\r\n\r\n" + string(embeddedFinal)
	}
	newBody := strings.Join(segments, delim)

	// 4. Reassemble the DSN and re-sign it as a NEW message with MAIL FROM <>.
	//    The inbound DSN's OWN instance and signature are dropped here: they
	//    belong to the DSN we received, which has already been authenticated
	//    (§12.1.2) and is not being continued. Leaving them makes the new
	//    instance m=2 on a chain whose i=1 is somebody else's.
	var assembled bytes.Buffer
	for _, h := range headers {
		if strings.EqualFold(h.Name, "message-instance") ||
			strings.EqualFold(h.Name, "dkim2-signature") {
			continue
		}
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

// topMIVersion returns the highest Message-Instance m= of a raw message.
func topMIVersion(raw []byte) (int, bool) {
	headers, _, err := parseHeaders(bytes.NewReader(raw))
	if err != nil {
		return 0, false
	}
	top, found := 0, false
	for _, h := range headers {
		if strings.EqualFold(h.Name, "message-instance") {
			if mi, err := parseMI(h.Raw); err == nil && mi.Version > top {
				top, found = mi.Version, true
			}
		}
	}
	return top, found
}

// stripTopMI removes the highest-version Message-Instance header from a raw
// message. Used with stripTopSig when the Forwarder's whole hop comes off but
// undo could not run: the instance goes with the signature that covered it, or
// the returned message carries an instance above its own top signature, which
// is the spec-06 §11 "is not signed" PERMERROR for whoever receives it.
func stripTopMI(raw []byte) ([]byte, error) {
	headers, bodyReader, err := parseHeaders(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	body := new(bytes.Buffer)
	body.ReadFrom(bodyReader)

	maxV, found := -1, false
	for _, h := range headers {
		if strings.EqualFold(h.Name, "message-instance") {
			if mi, err := parseMI(h.Raw); err == nil && mi.Version > maxV {
				maxV, found = mi.Version, true
			}
		}
	}
	if !found {
		return raw, nil
	}
	var out bytes.Buffer
	for _, h := range headers {
		if strings.EqualFold(h.Name, "message-instance") {
			if mi, err := parseMI(h.Raw); err == nil && mi.Version == maxV {
				continue
			}
		}
		out.WriteString(h.Raw)
	}
	out.WriteString("\r\n")
	out.Write(body.Bytes())
	return out.Bytes(), nil
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

// originSig returns the LOWEST-sequence DKIM2-Signature of a raw message. For
// a DSN that is the signature of the system that generated it: §12.1.1 makes a
// DSN a new message with exactly one signature, and if that DSN is itself
// forwarded onwards, i=1 is still its originator.
func originSig(raw []byte) (*DKIM2Signature, error) {
	headers, _, err := parseHeaders(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	var bottom *DKIM2Signature
	for _, h := range headers {
		if strings.EqualFold(h.Name, "dkim2-signature") {
			if sig, err := parseSig(h.Raw); err == nil {
				if bottom == nil || sig.Sequence < bottom.Sequence {
					bottom = sig
				}
			}
		}
	}
	if bottom == nil {
		return nil, fmt.Errorf("no DKIM2-Signature found")
	}
	return bottom, nil
}

// topSigMailFrom returns the MAIL FROM of the highest-sequence DKIM2-Signature.
func topSigMailFrom(raw []byte) (string, error) {
	top, err := topSig(raw)
	if err != nil {
		return "", fmt.Errorf("no DKIM2-Signature to derive upstream MAIL FROM")
	}
	return top.MailFrom, nil
}
