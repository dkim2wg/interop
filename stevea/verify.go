package dkim2

//go:generate go run internal/generate/validationerrors/validationerrors.go --label=error_names.txt --output=verify_errors.go

import (
	"bytes"
	"cmp"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/mail"
	"regexp"
	"slices"
	"strings"
)

// KeyResolver fetches a public key for a selector / domain
// pair, typically by performing a DNS query.
type KeyResolver interface {
	// Resolve returns DNS-style results for a selector
	// domain pair. A NOERROR or NXDOMAIN response will
	// return a string slice of TXT record payloads.
	// Anything else will return an error.
	Resolve(ctx context.Context, selector string, domain string) ([]string, error)
}

// ErrVerify is an error that represents a failure
// to verify a DKIM2 signed message. It is a error,
// but is intended to also be used in user-facing
// rejections, bounces and Authentication-Results headers.
type ErrVerify interface {
	error
	State() VerificationState
}

// VerificationState represents the broad pass/fail
// result of a verification, using the RFC 8601 terms.
type VerificationState string

const (
	StatePass      VerificationState = "pass"
	StateFail      VerificationState = "fail"
	StateTempError VerificationState = "temperror"
	StatePermError VerificationState = "permerror"
)

// VerificationResult contains the result of verifying
// a DKIM2 signed email.
type VerificationResult struct {
	Err      ErrVerify
	Domain   string
	D2I      int
	Selector string
	Exploded bool
	Feedback bool
	Flags    map[string]struct{}
}

func newResult(err error) *VerificationResult {
	res := &VerificationResult{
		Flags: make(map[string]struct{}),
	}
	if err != nil {
		res.setError(err)
	}
	return res
}

// State returns whether the email was verified or not,
// using RFC 8601 states.
func (v *VerificationResult) State() VerificationState {
	if v.Err == nil {
		return StatePass
	}
	return v.Err.State()
}

// AuthenticationResult returns a string description of
// the result, suitable for use in an Authentication-Results
// header.
func (v *VerificationResult) AuthenticationResult() string {
	if v.Err == nil {
		return "; dkim2=pass"
	}
	var builder strings.Builder
	_, _ = fmt.Fprintf(&builder, "; dkim2=%s (%s)", v.State(), v.Err.Error())
	if v.Domain != "" {
		_, _ = fmt.Fprintf(&builder, "; header.d=%s", v.Domain)
	}
	if v.Selector != "" {
		_, _ = fmt.Fprintf(&builder, " header.s=%s", v.Selector)
	}
	if v.D2I != 0 {
		_, _ = fmt.Fprintf(&builder, " header.i=%d", v.D2I)
	}
	return builder.String()
}

// ErrInternal wraps a Go error that happened during
// message processing.
type ErrInternal struct {
	Err error
}

func (e ErrInternal) Error() string {
	return "internal error"
}

func (e ErrInternal) State() VerificationState {
	return StateFail
}

func (e ErrInternal) Unwrap() error {
	return e.Err
}

func (v *VerificationResult) setError(err error) {
	if err == nil {
		return
	}
	e, ok := err.(ErrVerify)
	if ok {
		v.Err = e
		return
	}
	v.Err = ErrInternal{
		Err: err,
	}
}

type VerifyOptions struct {
	IgnoreTimestamp bool
	Resolver        KeyResolver
	MailFrom        string
	RcptTo          []string
}

func (opts *VerifyOptions) validate() error {
	if opts.Resolver == nil {
		if DefaultResolver != nil {
			opts.Resolver = DefaultResolver
		} else {
			var err error
			opts.Resolver, err = NewDnsResolver("")
			if err != nil {
				return err
			}
		}
	}
	return nil
}

var DefaultResolver = func() KeyResolver {
	r, err := NewDnsResolver("")
	if err != nil {
		return nil
	}
	return r
}()

//XXXX do chain-walking VerifyAll, generating lists
//of all D2, MI headers and applying the recipes as we
//walk back D2, removing sigs and associated MI as we
//go. Have a struct that contains the header lists,
//a mail.Header and body, and a function that steps
//that back to a given point. Use that for dkim2undo,
//and VerifyAll.

// Verify verifies the newest DKIM2 signature of a message,
// as required at email receipt time to allow rejection
// if needed.
func Verify(ctx context.Context, r io.Reader, opts VerifyOptions) *VerificationResult {
	err := opts.validate()
	if err != nil {
		return newResult(err)
	}

	msg, err := mail.ReadMessage(r)
	if err != nil {
		return newResult(err)
	}
	// Parse all the DKIM2-Signature headers
	d2headers, miHeaders, err := parseD2Headers(msg.Header)
	if err != nil {
		return newResult(err)
	}
	result, err := verifyMessage(ctx, msg, opts.MailFrom, opts.RcptTo, d2headers, miHeaders, opts)
	if err != nil {
		if result == nil {
			result = newResult(nil)
		}
		result.setError(err)
	}
	return result
}

// VerifyAll verifies all DKIM2 signatures of a message.
func VerifyAll(ctx context.Context, r io.Reader, opts VerifyOptions) *VerificationResult {
	err := opts.validate()
	if err != nil {
		return newResult(err)
	}

	msg, err := mail.ReadMessage(r)
	if err != nil {
		return newResult(err)
	}
	// Parse all the DKIM2-Signature headers
	d2headers, miHeaders, err := parseD2Headers(msg.Header)
	if err != nil {
		return newResult(err)
	}

	body, err := io.ReadAll(msg.Body)
	if err != nil {
		return newResult(err)
	}
	headers := NormalizedHeaders(msg.Header)
	result := newResult(nil)

	// TODO(steve): Check mailfrom / rcptto chains

	// For each signature
	for len(d2headers) > 0 {
		lastD2 := d2headers[len(d2headers)-1]
		// Verify the signature for the state of the
		// message at the time it was assigned
		res, err := verifyMessage(ctx, &mail.Message{
			Header: headers,
			Body:   bytes.NewReader(body),
		}, "", nil, d2headers, miHeaders, opts)
		if err != nil {
			res.setError(err)
			return res
		}
		if res.Exploded {
			result.Exploded = true
		}
		if res.Feedback {
			result.Feedback = true
		}
		for flag := range res.Flags {
			result.Flags[flag] = struct{}{}
		}

		// Revert changes recorded in Message-Instance
		// headers
		m := lastD2.MIRevision
		for len(miHeaders) > 0 &&
			miHeaders[len(miHeaders)-1].Revision >= m {
			recipe := miHeaders[len(miHeaders)-1].Recipes
			if recipe != nil {
				headers, err = recipe.Header(headers)
				if err != nil {
					res.setError(err)
					return res
				}
				var buff bytes.Buffer
				err = recipe.Body(bytes.NewReader(body), &buff)
				if err != nil {
					res.setError(err)
					return res
				}
				body = buff.Bytes()
			}
			miHeaders = miHeaders[:len(miHeaders)-1]
		}
		d2headers = d2headers[:len(d2headers)-1]
	}

	return result
}

// parseD2Headers parses the Messsage-Instance and
// DKIM2-Signature headers from a mail.Header and returns
// them as two lists in ascending i=/m= order
func parseD2Headers(header mail.Header) ([]*Signature, []*MessageInstance, error) {
	d2RawHeaders := header[hdrDKIM2Signature]
	if len(d2RawHeaders) == 0 {
		// Bail early, so we don't need to deal with this
		// case later
		return nil, nil, ErrSignatureMissing{
			Sequence: 1,
		}
	}

	d2headers := make([]*Signature, 0, len(d2RawHeaders))

	maxM := 0
	for _, h := range d2RawHeaders {
		d2, err := ParseSignature(h)
		if err != nil {
			return nil, nil, err
		}

		d2headers = append(d2headers, d2)
		if d2.MIRevision > maxM {
			maxM = d2.MIRevision
		}
	}

	// Sort the DKIM2-Signature headers by i=, then
	// we can check for duplicates and missing values.
	slices.SortFunc(d2headers, func(a, b *Signature) int {
		return cmp.Compare(a.Sequence, b.Sequence)
	})

	for n, d2 := range d2headers {
		if d2.Sequence == n+1 {
			continue
		}
		if d2.Sequence == n {
			// duplicate i=
			return nil, nil, ErrSignatureSyntaxError{
				Sequence: d2.Sequence,
				Header:   d2.Original,
			}
		}
		return nil, nil, ErrSignatureMissing{
			Sequence: n + 1,
		}
	}

	// Parse all the Message-Instance headers
	miRawHeaders := header[hdrMessageInstance]
	miHeaders := make([]*MessageInstance, 0, len(miRawHeaders))
	for _, h := range miRawHeaders {
		mi, err := ParseMessageInstance(h)
		if err != nil {
			return nil, nil, err
		}
		miHeaders = append(miHeaders, mi)
		if mi.Revision > maxM {
			return nil, nil, ErrMessageInstanceIsNotSigned{
				MInstance: mi.Revision,
			}
		}
	}

	// Sort the Message-Instance headers by i=, then
	// we can check for duplicates and missing values.
	slices.SortFunc(miHeaders, func(a, b *MessageInstance) int {
		return cmp.Compare(a.Revision, b.Revision)
	})

	for n, mi := range miHeaders {
		if mi.Revision == n+1 {
			continue
		}
		if mi.Revision == n {
			// duplicate m=
			return nil, nil, ErrMessageInstanceSyntaxError{
				MInstance: mi.Revision,
				Header:    mi.Original,
			}
		}
		return nil, nil, ErrMessageInstanceMissing{
			MInstance: n + 1,
		}
	}
	return d2headers, miHeaders, nil
}

var replaceSignatureRe = regexp.MustCompile(`((?:^|;)s=)[^;]+`)

// verifyMessage validates the most recent DKIM2-Signature for a message.
// It may read some or all of msg.Body.
func verifyMessage(ctx context.Context, msg *mail.Message,
	mailFrom string, rcptTo []string, d2headers []*Signature,
	miHeaders []*MessageInstance, opts VerifyOptions) (*VerificationResult, error) {
	result := &VerificationResult{}

	// 10.3
	// Reject anything with a timestamp more than 14 days old
	timeStampStale := Now() - 3600*14*24
	for _, d2 := range d2headers {
		if d2.Timestamp < timeStampStale && !opts.IgnoreTimestamp {
			return result, ErrSignatureExpired{
				Sequence: d2.Sequence,
			}
		}
	}

	// 10.4 Check the chain of custody
	lastD2 := d2headers[len(d2headers)-1]
	result.Domain = lastD2.Domain
	result.D2I = lastD2.Sequence
	result.Exploded = lastD2.Exploded
	result.Feedback = lastD2.Feedback
	for _, flag := range lastD2.Flags() {
		result.Flags[flag] = struct{}{}
	}
	if rcptTo != nil {
		// MAIL FROM must match value in signature
		if foldEmailDomain(mailFrom) !=
			foldEmailDomain(lastD2.MailFrom) {
			return result, ErrMailFromValueDidNotMatch{
				Value: mailFrom,
			}
		}

		// All RCPT TO values must match a value in signature
		allowedRcptTo := make(map[string]struct{}, len(lastD2.RcptTo))
		for _, rcptTo := range lastD2.RcptTo {
			allowedRcptTo[foldEmailDomain(rcptTo)] = struct{}{}
		}
		for _, rcptTo := range rcptTo {
			_, ok := allowedRcptTo[foldEmailDomain(rcptTo)]
			if !ok {
				return result, ErrRcptToValueDidNotMatch{
					Value: rcptTo,
				}
			}
		}

		// The MAIL FROM domain must match the d= signing
		// domain, either exactly or as a subdomain of it.
		if mailFrom != "<>" {
			at := strings.LastIndex(mailFrom, "@")
			mailFromDomain := "." + strings.ToLower(mailFrom[at+1:])
			signingDomain := "." + strings.ToLower(lastD2.Domain)
			if !strings.HasSuffix(mailFromDomain, signingDomain) {
				return result, ErrMailFromAndDoNotMatch{}
			}
		}
	}
	// 8.5 Generate sorted Message-Instance and
	// DKIM2-Signature headers for hashing.
	var buff bytes.Buffer
	for _, mi := range miHeaders {
		buff.WriteString(lwrMessageInstance)
		buff.WriteString(":")
		buff.WriteString(removeWhitespace(mi.Original))
		buff.WriteString("\r\n")
	}

	for _, d2 := range d2headers[:len(d2headers)-1] {
		buff.WriteString(lwrDKIM2Signature)
		buff.WriteString(":")
		buff.WriteString(removeWhitespace(d2.Original))
		buff.WriteString("\r\n")
	}

	finalD2 := removeWhitespace(lastD2.Original)
	finalD2 = replaceSignatureRe.ReplaceAllStringFunc(finalD2, func(s string) string {
		sigs := strings.Split(s, ",")
		modified := make([]string, len(sigs))
		for i, sig := range sigs {
			// Split into selector:name:signature
			// parts[0] will also contain any leading "s="
			parts := strings.Split(sig, ":")
			if len(parts) != 3 { // :shrug:
				modified[i] = sig
				continue
			}
			modified[i] = parts[0] + ":" + parts[1] + ":"
		}
		return strings.Join(modified, ",")
	})
	buff.WriteString(lwrDKIM2Signature)
	buff.WriteString(":")
	buff.WriteString(finalD2)
	buff.WriteString("\r\n")
	signedHeaders := buff.Bytes()

	// Check signatures
	sigErrors := make([]error, len(lastD2.Signatures))
	errCount := 0
	for i, sig := range lastD2.Signatures {
		err := verifySignature(ctx, lastD2, sig, signedHeaders, opts.Resolver)
		sigErrors[i] = err
		if err != nil {
			errCount++
		}
	}
	if errCount > 0 {
		selNames := make([]string, len(lastD2.Signatures))
		for i, sig := range lastD2.Signatures {
			selNames[i] = sig.Selector
		}
		if errCount == len(sigErrors) {
			if errCount == 1 {
				return result, sigErrors[0]
			}
			fails := make([]string, len(sigErrors))
			for i, sig := range sigErrors {
				fails[i] = sig.Error()
			}
			return result, ErrFailSignatureValidationFailed{
				Sequence: lastD2.Sequence,
				Detail:   strings.Join(fails, ", "),
			}
		}
		passFail := make([]string, 0, len(lastD2.Signatures))
		for i, sig := range lastD2.Signatures {
			if sigErrors[i] == nil {
				passFail[i] = sig.Selector + " passed"
			} else {
				passFail[i] = fmt.Sprintf("%s failed (%s)", sig.Selector, sigErrors[i].Error())
			}
		}
		return result, ErrFailSignatureValidationFailed{
			Sequence: lastD2.Sequence,
			Detail:   strings.Join(passFail, ", "),
		}
	}
	// All signatures passed, time to validate the hashes

	lastMI := miHeaders[len(miHeaders)-1]
	seenSHA256 := false
	for _, hash := range lastMI.Hashes {
		if hash.Name == "sha256" {
			seenSHA256 = true
		}
	}
	if !seenSHA256 {
		// No sha256 hash in Message-Instance
		return result, ErrMessageInstanceSyntaxError{
			MInstance: lastMI.Revision,
			Header:    lastMI.Original,
			Detail:    "missing required sha256 hash",
			Err:       errors.New("no sha256 hash found"),
		}
	}

	hashes, err := HashMessage(msg.Body, NormalizedHeaders(msg.Header))
	if err != nil {
		// Currently can't happen.
		return result, err
	}

	for _, hashFromHeader := range lastMI.Hashes {
		for _, hash := range hashes {
			if hash.Name == hashFromHeader.Name {
				if !bytes.Equal(hashFromHeader.HeaderHash, hash.HeaderHash) {
					return result, ErrFailMessageInstanceHeaderHashValueMismatch{
						MInstance: lastMI.Revision,
						Value:     hash.String(),
					}
				}
				if !bytes.Equal(hashFromHeader.BodyHash, hash.BodyHash) {
					return result, ErrFailMessageInstanceBodyHashValueMismatch{
						MInstance: lastMI.Revision,
						Value:     hash.String(),
					}
				}
			}
		}
	}
	return result, nil
}

func verifySignature(ctx context.Context, lastD2 *Signature, sig Sig, signedHeaders []byte, resolver KeyResolver) error {
	txtRecords, err := resolver.Resolve(ctx, sig.Selector, lastD2.Domain)
	if err != nil {
		return ErrTempSignaturePublicKeyValueCouldNotBeFetched{
			Sequence: lastD2.Sequence,
			Value:    HostnameForKey(sig.Selector, lastD2.Domain),
			Err:      err,
		}
	}
	if len(txtRecords) == 0 {
		return ErrSignaturePublicKeyValueDoesNotExist{
			Sequence: lastD2.Sequence,
			Value:    HostnameForKey(sig.Selector, lastD2.Domain),
		}
	}
	if len(txtRecords) > 1 {
		return ErrSignaturePublicKeyValueHasMultipleRecords{
			Sequence: lastD2.Sequence,
			Value:    HostnameForKey(sig.Selector, lastD2.Domain),
		}
	}

	var algorithm, key string
	for i, kv := range strings.Split(txtRecords[0], ";") {
		k, v, found := strings.Cut(kv, "=")
		if !found {
			if strings.TrimSpace(kv) == "" {
				continue
			}
			return ErrSignaturePublicKeyValueHasASyntaxError{
				Sequence: lastD2.Sequence,
				Value:    HostnameForKey(sig.Selector, lastD2.Domain),
				Err:      fmt.Errorf("no \"=\" found in %q", kv),
			}
		}
		k = strings.ToLower(strings.TrimSpace(k))

		v = strings.TrimSpace(v)
		switch k {
		case "v":
			if i != 0 {
				return ErrSignaturePublicKeyValueHasASyntaxError{
					Sequence: lastD2.Sequence,
					Value:    HostnameForKey(sig.Selector, lastD2.Domain),
					Detail:   "\"v=\" must be first field",
					Err:      fmt.Errorf("\"v=\" must be first field and equal \"DKIM1\""),
				}
			}
			if v != "DKIM1" {
				return ErrSignaturePublicKeyValueHasASyntaxError{
					Sequence: lastD2.Sequence,
					Value:    HostnameForKey(sig.Selector, lastD2.Domain),
					Detail:   fmt.Sprintf("\"v=%s\" should be \"v=DKIM1\"", v),
					Err:      fmt.Errorf("\"v=\" equal \"DKIM1\""),
				}
			}
		case "k":
			switch v {
			case "rsa":
				if sig.Name != "rsa-sha256" {
					return ErrSignaturePublicKeyValueAlgorithmMismatch{
						Sequence: lastD2.Sequence,
						Value:    HostnameForKey(sig.Selector, lastD2.Domain),
					}
				}
			case "ed25519":
				if sig.Name != "ed25519-sha256" {
					return ErrSignaturePublicKeyValueAlgorithmMismatch{
						Sequence: lastD2.Sequence,
						Value:    HostnameForKey(sig.Selector, lastD2.Domain),
					}
				}
			default:
				return ErrSignaturePublicKeyValueHasASyntaxError{
					Sequence: lastD2.Sequence,
					Value:    HostnameForKey(sig.Selector, lastD2.Domain),
					Detail:   fmt.Sprintf("\"k=%s\" not supported", k),
					Err:      fmt.Errorf("unrecognized \"k=\": %q", v),
				}
			}
			algorithm = v
		case "p":
			if v == "" {
				return ErrSignaturePublicKeyValueHasBeenRevoked{
					Sequence: lastD2.Sequence,
					Value:    HostnameForKey(sig.Selector, lastD2.Domain),
				}
			}
			key = removeWhitespace(v)
		}
	}
	rawKey, err := base64.StdEncoding.Strict().DecodeString(key)
	if err != nil {
		return ErrSignaturePublicKeyValueHasASyntaxError{
			Sequence: lastD2.Sequence,
			Value:    HostnameForKey(sig.Selector, lastD2.Domain),
			Err:      err,
		}
	}
	switch algorithm {
	case "rsa":
		// See https://www.rfc-editor.org/errata/eid3017
		pub, err := x509.ParsePKIXPublicKey(rawKey)
		if err != nil {
			pub, err = x509.ParsePKCS1PublicKey(rawKey)
			if err != nil {
				return ErrSignaturePublicKeyValueHasASyntaxError{
					Sequence: lastD2.Sequence,
					Value:    HostnameForKey(sig.Selector, lastD2.Domain),
					Err:      err,
				}
			}
		}
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return ErrSignaturePublicKeyValueHasASyntaxError{
				Sequence: lastD2.Sequence,
				Value:    HostnameForKey(sig.Selector, lastD2.Domain),
				Detail:   "not an RSA public key",
				Err:      fmt.Errorf("expected type *rsa.PublicKey, got %T", pub),
			}
		}
		if rsaPub.Size()*8 < 1024 {
			return ErrSignaturePublicKeyValueHasASyntaxError{
				Sequence: lastD2.Sequence,
				Value:    HostnameForKey(sig.Selector, lastD2.Domain),
				Detail:   fmt.Sprintf("RSA public key size too small, %d bits", rsaPub.Size()*8),
				Err:      fmt.Errorf("key is too short: want 1024 bits, has %v bits", rsaPub.Size()*8),
			}
		}
		hashed := sha256.Sum256(signedHeaders)
		err = rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, hashed[:], sig.Signature)
		if err != nil {
			return ErrFailSignaturePublicKeyValueIncorrectSignature{
				Sequence: lastD2.Sequence,
				Value:    HostnameForKey(sig.Selector, lastD2.Domain),
				Err:      err,
			}
		}
	case "ed25519":
		if len(rawKey) != ed25519.PublicKeySize {
			return ErrSignaturePublicKeyValueHasASyntaxError{
				Sequence: lastD2.Sequence,
				Value:    HostnameForKey(sig.Selector, lastD2.Domain),
				Detail:   fmt.Sprintf("invalid ed25519 key size, %d bytes", len(rawKey)),
			}
		}
		hashed := sha256.Sum256(signedHeaders)
		ed25519Pub := ed25519.PublicKey(rawKey)
		//fmt.Printf("signedHeaders:\n---\n%s\n---\nhash: %x\nkey: %x\n", signedHeaders, hashed, rawKey)
		if !ed25519.Verify(ed25519Pub, hashed[:], sig.Signature) {
			return ErrFailSignaturePublicKeyValueIncorrectSignature{
				Sequence: lastD2.Sequence,
				Value:    HostnameForKey(sig.Selector, lastD2.Domain),
			}
		}
	default:
		return ErrSignaturePublicKeyValueHasASyntaxError{
			Sequence: lastD2.Sequence,
			Value:    HostnameForKey(sig.Selector, lastD2.Domain),
			Err:      fmt.Errorf("unexpected signature algorithm: %q", algorithm),
		}
	}

	return nil
}

func foldEmailDomain(s string) string {
	at := strings.LastIndex(s, "@")
	if at == -1 {
		return s
	}
	return s[:at+1] + strings.ToLower(s[at+1:])
}

/*
# Verifier Actions {#verifier_actions}

This section discusses the detail of the actions taken by a
Verifier. In essence
this will involve repeating all the actions taken by a Signer to
produce a Message-Instance or DKIM2-Signature header field. To
avoid a lot of repetition these actions will not be spelled out
in detail. Once a hash value has been calculated it is then
compared with the value reported by the Signer, or the Signer's
public key is used to determine whether a signature that has
been provided is correct.

When a Verifier is determining whether a particular DKIM2-Signature
header field it MUST consider the state of the message when that
header field was added to the message. That means it MUST first apply
all relevant recipes to reconstruct the body and header fields and it
MUST ignore any Message-Instance and DKIM2-Signature fields that
were added after that point.

## Output States

For compatibility with the Authentication-Results header field defined
in [RFC8601] a verification will result in one of four states:

PASS:  The message was successfully verified.

FAIL:  The message could be verified but a hash or signature was not
       correct.

PERMERROR:  The message could not be verified due to some error that
      is unrecoverable, such as a required header field being absent
      or malformed.

TEMPERROR:  The message could not be verified due a temporary
      inability to retrieve a public key. A later attempt may
      produce a different.

A Verifier MAY cease verifying once a single failure is detected.

Verifiers wishing to communicate the results of verification to other
parts of the mail system may do so in whatever manner they see fit. If
they wish to provide a human-readable string to describe a failure
to verify (any state except PASS) then in order to provide the
maximum possible assistance to senders they SHOULD use the text
strings specified in this document. These human-readable messages
are described with m=`<x>` or tag=`<y>` placeholders, the `<x>` and `<y>` MUST
be replaced with the relevant ordinal or tag name (without the < and
> characters). Similarly `<value>` MUST be replaced by a relevant
string for the particular message.

If the verification is being performed during an SMTP protocol
conversation the human-readable string SHOULD be part of the
5xx or 4xx response string.

If the results of the verification are being communicated in a
Delivery Status Notification message ({{RFC3461}}) the
human-readable string should be included.

If, by local policy, a system wishes to accept a message which
has failed authentication it might choose to add an email header
field to the message before passing it on.  Any such header field
SHOULD include the human-readable string and
SHOULD be inserted before any existing DKIM2-Signature or pre-existing
authentication status header fields in the header field block.  The
Authentication-Results: header field ([RFC8601]) MAY be used for this
purpose. It should be noted that any "Authentication-Results" header
field will count as a modification to the email if any further
DKIM2-Signature header fields are to be generated.

## Ensure that the DKIM2 Header Fields are Valid

Verifiers MUST meticulously validate the format and values of all
relevant Message-Instance and DKIM2-Signature header fields. It MUST
also ensure that all required instances of these header fields are
present and that all required tags are present. Recall however
that unknown tags MUST be ignored.

As a special case, there MUST not be a Message-Instance field
with a higher m= value than occurs in any DKIM2-Signature field.

Possible errors:

    PERMERROR Message-Instance m=<x> missing
    PERMERROR Message-Instance m=<x> syntax error
    PERMERROR Message-Instance m=<x> tag=<y> missing
    PERMERROR Message-Instance m=<x> is not signed
    PERMERROR DKIM2-Signature i=<x> missing
    PERMERROR DKIM2-Signature i=<x> syntax error
    PERMERROR DKIM2-Signature i=<x> tag=<y> missing

## Check the timestamps

Verifiers SHOULD return a failure it is more than 14 days since the
timestamp recorded in the "t=" tag of any DKIM2-Signature header field.

Possible errors:

    PERMERROR DKIM2-Signature i=<x> signature expired

## Check the Chain-of-Custody

As explained in {{chain-of-custody}} a Verifier MUST check an exact
match between the MAIL FROM and RCPT TO parameters used when delivering
a message and the values found in the mf= and rt= tags of the highest
numbered DKIM2-Signature header field. There may be extra values
in the rt= value, but all RCPT TO values actually used for
delivery MUST be present.

The values of domains MUST BE put into lower-case before doing these
checks. As is usual in email protocols the case of the local part of
an email address is assumed to matter. Note that these checks MUST NOT
use the relaxed domain match algorithm.

A Verifier SHOULD check that there is a relaxed domain match
(see {relaxed-domain-match}) between the signing domain of the
most recently applied DKIM2-Signature header field and the
mf= value in that header field.

Possible errors:

    PERMERROR: MAIL FROM <value> did not match
    PERMERROR: RCPT TO <value> did not match
    PERMERROR: MAIL FROM and d= do not match

## Fetch the Public Key

The public keys of all the signatures in DKIM2-Signature fields are
needed to complete the verification process. Details of key management and
representation are described in {{key_management}} and [DKIMKEYS].
The Verifier MUST validate the key record and MUST not use any public
key records that are malformed.

Note that DNS timeouts MUST be reported as TEMPERROR but a DNS
result that indicates the key is absent MUST be reported as a
PERMERROR. Additionally, as [DKIMKEYS] makes clear, if more than
one record is returned this is an error. The human-readable error
message SHOULD provide the selector value so that it is clear which
key has caused a problem.

Note that [DKIMKEYS] has retired the h= field and DKIM2 implementations
MUST ignore this tag if it is present.

Possible errors:

    TEMPERROR: DKIM2-Signature i=<x> public key <value> could not be fetched
    PERMERROR: DKIM2-Signature i=<x> public key <value> does not exist
    PERMERROR: DKIM2-Signature i=<x> public key <value> has multiple records
    PERMERROR: DKIM2-Signature i=<x> public key <value> has a syntax error
    PERMERROR: DKIM2-Signature i=<x> public key <value> algorithm mismatch
    PERMERROR: DKIM2-Signature i=<x> public key <value> has been revoked

## Perform the Signature Verification Calculation

Verifying a signature consists of actions semantically equivalent to the
following steps:

1.  Prepare a canonicalized version of the Message-Instance and DKIM2-Signature
    header fields as described in {{calculate-signature}}. The signature value(s)
    themselves will need to be removed to correspond with what was actually
    signed. Note that this canonicalized version does not actually replace
    the original content.

1.  Use the relevant public key value(s) to check the signature(s).

1.  If there is more than one signature provided then they MUST all be
    checked if the Verifier is able to do so. If any signature fails then
    an error SHOULD be reported. If all signatures that can be checked fail
    then PERMFAIL MUST be reported.

1.  If some signatures fail and other pass then any error that is
    reported should provide that information (e.g. PERMFAIL "rsa-sha256
    signature passed, ed25519-sha256 signature failed").

The reasoning for requiring that all signatures pass is that if a signature
scheme has recently become deprecated because it is known to be cryptographically
flawed then Signers will use a second (unbroken) signature scheme. However, such
a Signer may still provide the other signature for the benefit of Verifiers
that have yet to upgrade -- reasoning perhaps that attacks are too expensive
to be a very significant security issue. A Verifier that determines that
one signature passes whilst the other fails may well be in a position to
prevent an attack.

Possible errors:

    FAIL: DKIM2-Signature i=<x> public key <value> incorrect signature

## Validating Body and Header hashes

Verifying a hash value requires a Verifier to repeat the hash calculation
performed by the Signer as set out in {{computing-body-hash}}
and {{computing-body-hash}}. The values can then be directly compared.

Since there may be more than one hash algorithm given the human-readable
error message SHOULD indicate which algorithm's result failed to match.

Possible errors:

    FAIL: Message Instance m=<x> header hash <value> mismatch
    FAIL: Message Instance m=<x> body hash <value> mismatch

# Delivery Status Notifications in the DKIM2 ecosystem {#bounce}

In the DKIM2 ecosystem, when a message cannot be delivered then
this is reported to the sending machine by means of an {{RFC5321}}
return code or, if the SMTP session has completed, by generating
a Delivery Status Notification (DSN, as defined in {{RFC3461}}.

A DSN MUST be addressed to the MTA that sent the message. This
prevents "backscatter" by passing failures back along the chain
of MTAs that were in involved in passing the message forwards. This
is achieved by using the mf= tag from the highest numbered
DKIM2-Signature field. If this field is null ("mf=<>") then a DSN
MUST NOT be sent.

*/
