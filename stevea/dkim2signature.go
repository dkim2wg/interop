package dkim2

import (
	"bytes"
	"cmp"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/mail"
	"slices"
	"strconv"
	"strings"
	"unicode"
)

// Sig is one selector / algorithm name / signature data tuple.
type Sig struct {
	Selector  string `json:"selector"`
	Name      string `json:"name"`
	Signature []byte `json:"signature"`
}

func (s Sig) String() string {
	var builder strings.Builder
	builder.WriteString(s.Selector)
	builder.WriteByte(':')
	builder.WriteString(s.Name)
	builder.WriteByte(':')
	encoder := base64.NewEncoder(base64.StdEncoding, &builder)
	_, _ = encoder.Write(s.Signature)
	_ = encoder.Close()
	return builder.String()
}

// Signature represents the content of a DKIM2-Signature header.
type Signature struct {
	Sequence     int      `json:"i"`
	MIRevision   int      `json:"m"`
	Nonce        string   `json:"n"`
	Timestamp    int64    `json:"t"`
	MailFrom     string   `json:"mf"`
	RcptTo       []string `json:"rt"`
	Domain       string   `json:"d"`
	Signatures   []Sig    `json:"s"`
	Exploded     bool     `json:"f-exploded"`
	DoNotExplode bool     `json:"f-do-not-explode"`
	DoNotModify  bool     `json:"f-do-not-modify"`
	Feedback     bool     `json:"f-feedback"`
	ExtraFlags   []string `json:"f-extra"`
	Original     string   `json:"original"`
}

// ParseSignature creates a new Signature from a DKIM2-Signature header.
func ParseSignature(h string) (*Signature, error) {
	tags, err := NewTags(hdrDKIM2Signature, h, "i")
	if err != nil {
		return nil, err
	}
	ret := Signature{
		Original: h,
	}

	seq, ok := tags.Get("i")
	if !ok {
		return nil, ErrMissingTag{
			Name: hdrDKIM2Signature,
			V:    h,
			Tag:  "i",
		}
	}
	seqI, err := strconv.ParseInt(seq, 10, 32)
	if err != nil {
		return nil, ErrInvalidTag{
			Name:   hdrDKIM2Signature,
			V:      h,
			Tag:    "i",
			TagVal: seq,
			Err:    err,
		}
	}
	ret.Sequence = int(seqI)

	rev, ok := tags.Get("m")
	if !ok {
		return nil, ErrSignatureTagMissing{
			Sequence: ret.Sequence,
			Tag:      "m",
			Header:   h,
		}
	}
	revI, err := strconv.ParseInt(rev, 10, 32)
	if err != nil {
		return nil, ErrSignatureSyntaxError{
			Sequence: ret.Sequence,
			Header:   h,
			Err: ErrInvalidTag{
				Name:   hdrDKIM2Signature,
				V:      h,
				Tag:    "m",
				TagVal: rev,
				Err:    err,
			},
		}
	}
	ret.MIRevision = int(revI)

	nonce, ok := tags.Get("n")
	if ok {
		if len(nonce) > 64 {
			return nil, ErrSignatureSyntaxError{
				Sequence: ret.Sequence,
				Header:   h,
				Err: ErrInvalidTag{
					Name:   hdrDKIM2Signature,
					V:      h,
					Tag:    "n",
					TagVal: nonce,
					Err:    errors.New("cannot be longer than 64 characters"),
				},
			}
		}
		ret.Nonce = nonce
	}

	timestamp, ok := tags.Get("t")

	if !ok {
		return nil, ErrSignatureTagMissing{
			Sequence: ret.Sequence,
			Header:   h,
			Tag:      "t",
		}
	}
	ret.Timestamp, err = strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return nil, ErrSignatureSyntaxError{
			Sequence: ret.Sequence,
			Header:   h,
			Err: ErrInvalidTag{
				Name:   hdrDKIM2Signature,
				V:      h,
				Tag:    "t",
				TagVal: timestamp,
				Err:    err,
			},
		}
	}

	mailFrom, ok := tags.Get("mf")
	if !ok {
		return nil, ErrSignatureTagMissing{
			Sequence: ret.Sequence,
			Header:   h,
			Tag:      "mf",
		}
	}
	mf, err := base64.StdEncoding.Strict().DecodeString(mailFrom)
	if err != nil {
		return nil, ErrSignatureSyntaxError{
			Sequence: ret.Sequence,
			Header:   h,
			Err: ErrInvalidTag{
				Name:   hdrDKIM2Signature,
				V:      h,
				Tag:    "mf",
				TagVal: mailFrom,
				Err:    err,
			},
		}
	}
	if !isPrintString(mf) {
		return nil, ErrSignatureSyntaxError{
			Sequence: ret.Sequence,
			Header:   h,
			Err: ErrInvalidTag{
				Name:   hdrDKIM2Signature,
				V:      h,
				Tag:    "mf",
				TagVal: mailFrom,
				Err:    errors.New("decoded mf must contain only printable characters"),
			},
		}
	}
	ret.MailFrom = string(mf)

	rcptTo, ok := tags.Get("rt")
	if !ok {
		return nil, ErrSignatureTagMissing{
			Sequence: ret.Sequence,
			Tag:      "rt",
			Header:   h,
		}
	}
	for _, addr := range strings.Split(rcptTo, ",") {
		addr = strings.TrimSpace(addr)
		rt, err := base64.StdEncoding.Strict().DecodeString(addr)
		if err != nil {
			return nil, ErrSignatureSyntaxError{
				Sequence: ret.Sequence,
				Header:   h,
				Err: ErrInvalidTag{
					Name:   hdrDKIM2Signature,
					V:      h,
					Tag:    "rt",
					TagVal: rcptTo,
					Err:    err,
				},
			}
		}
		if !isPrintString(rt) {
			return nil, ErrSignatureSyntaxError{
				Sequence: ret.Sequence,
				Header:   h,
				Err: ErrInvalidTag{
					Name:   hdrDKIM2Signature,
					V:      h,
					Tag:    "rt",
					TagVal: rcptTo,
					Err:    errors.New("decoded rt must contain only printable characters"),
				},
			}
		}
		ret.RcptTo = append(ret.RcptTo, string(rt))
	}

	domain, ok := tags.Get("d")
	if !ok {
		return nil, ErrSignatureTagMissing{
			Sequence: ret.Sequence,
			Header:   h,
			Tag:      "d",
		}
	}
	ret.Domain = domain

	sel, ok := tags.Get("s")
	if !ok {
		return nil, ErrSignatureTagMissing{
			Sequence: ret.Sequence,
			Header:   h,
			Tag:      "s",
		}
	}
	sels := strings.Split(sel, ",")
	for _, s := range sels {
		parts := strings.Split(s, ":")
		if len(parts) != 3 {
			return nil, ErrSignatureSyntaxError{
				Sequence: ret.Sequence,
				Header:   h,
				Err: ErrInvalidTag{
					Name:   hdrDKIM2Signature,
					V:      h,
					Tag:    "s",
					TagVal: sel,
					Err:    errors.New("each signature should have three parts"),
				},
			}
		}
		sig, err := base64.StdEncoding.Strict().DecodeString(removeWhitespace(parts[2]))
		if err != nil {
			return nil, ErrSignatureSyntaxError{
				Sequence: ret.Sequence,
				Header:   h,
				Err: ErrInvalidTag{
					Name:   hdrDKIM2Signature,
					V:      h,
					Tag:    "s",
					TagVal: sel,
					Err:    err,
				},
			}
		}
		ret.Signatures = append(ret.Signatures, Sig{
			Selector:  removeWhitespace(parts[0]),
			Name:      removeWhitespace(parts[1]),
			Signature: sig,
		})
	}
	f, ok := tags.Get("f")
	if ok {
		for _, flag := range strings.Split(f, ",") {
			flag = strings.TrimSpace(flag)
			switch flag {
			case "exploded":
				ret.Exploded = true
			case "donotexplode":
				ret.DoNotExplode = true
			case "donotmodify":
				ret.DoNotModify = true
			case "feedback":
				ret.Feedback = true
			default:
				ret.ExtraFlags = append(ret.ExtraFlags, flag)
			}
		}
	}
	return &ret, nil
}

func (s *Signature) Flags() []string {
	flags := s.ExtraFlags
	if s.DoNotExplode {
		flags = append(flags, "donotexplode")
	}
	if s.DoNotModify {
		flags = append(flags, "donotmodify")
	}
	if s.Feedback {
		flags = append(flags, "feedback")
	}
	if s.Exploded {
		flags = append(flags, "exploded")
	}
	return flags
}

type indexedHeader struct {
	index   int
	payload []byte
}

func indexHeader(name string, h string, tag string) (indexedHeader, error) {
	tags, err := NewTags(hdrDKIM2Signature, h, "i")
	if err != nil {
		return indexedHeader{}, ErrMalformedHeader{
			Name: name,
			V:    h,
			Err:  err,
		}
	}
	idx, ok := tags.Get(tag)
	if !ok {
		return indexedHeader{}, ErrMissingTag{
			Name: name,
			V:    h,
			Tag:  tag,
		}
	}
	index, err := strconv.ParseInt(idx, 10, 32)
	if err != nil {
		return indexedHeader{}, ErrInvalidTag{
			Name:   name,
			V:      h,
			Tag:    tag,
			TagVal: idx,
			Err:    err,
		}
	}
	payload := make([]byte, 0, len(h)+len(name)+3)
	payload = append(payload, []byte(name)...)
	payload = append(payload, byte(':'))
	payload = append(payload, whitespaceRe.ReplaceAll([]byte(h), []byte{})...)
	payload = append(payload, []byte("\r\n")...)
	return indexedHeader{index: int(index), payload: payload}, nil
}

// ConcatHeadersForSigning generates the byte slice we need to
// sign for the header signature.
func (d *Signature) ConcatHeadersForSigning(headers mail.Header) ([]byte, error) {
	var payload []byte
	/*
		*  Place the header fields in order. First come the Message-Instance
		   header fields in ascending instance (m=) order. Second are the
		   DKIM2-Signature header fields in ascending sequence (i=) order.
		   Last of all is an incomplete DKIM2-Signature header field (the
		   one that this system is creating) with all tags present except
		   that the signature value(s) within the (s=) value are set to
		   the null string (""). The incomplete header field MUST be
		   unfolded, MUST have a trailing CRLF and MUST have spaces removed
		   in just the same way as the
		   complete header fields being processed.
	*/
	if messageInstances, ok := headers[hdrMessageInstance]; ok {
		miHeaders := make([]indexedHeader, 0, len(messageInstances))
		for _, mi := range messageInstances {
			ih, err := indexHeader(lwrMessageInstance, mi, "m")
			if err != nil {
				return nil, err
			}
			miHeaders = append(miHeaders, ih)
		}
		// If there are two headers with identical index something
		// is wrong with the header, so we'll never compare the payload,
		// but...
		slices.SortFunc(miHeaders, func(a, b indexedHeader) int {
			return cmp.Or(cmp.Compare(a.index, b.index),
				bytes.Compare(a.payload, b.payload))
		})
		if d.MIRevision == 0 {
			d.MIRevision = miHeaders[len(miHeaders)-1].index
		}
		for _, ih := range miHeaders {
			payload = append(payload, ih.payload...)
		}
	}

	if dkim2Headers, ok := headers[hdrDKIM2Signature]; ok {
		d2Headers := make([]indexedHeader, 0, len(dkim2Headers))
		for _, d2 := range dkim2Headers {
			dh, err := indexHeader(lwrDKIM2Signature, d2, "i")
			if err != nil {
				return nil, err
			}
			d2Headers = append(d2Headers, dh)
		}
		slices.SortFunc(d2Headers, func(a, b indexedHeader) int {
			return cmp.Or(cmp.Compare(a.index, b.index),
				bytes.Compare(a.payload, b.payload))
		})
		if d.Sequence == 0 {
			d.Sequence = d2Headers[len(d2Headers)-1].index
		}
		for _, dh := range d2Headers {
			payload = append(payload, dh.payload...)
		}
	}

	for i, v := range d.Signatures {
		v.Signature = []byte{}
		d.Signatures[i] = v
	}
	d2, err := indexHeader(lwrDKIM2Signature, d.ToString(), "i")
	if err != nil {
		return nil, err
	}
	payload = append(payload, d2.payload...)
	return payload, nil
}

func (d *Signature) AddSignature(selector string, signer crypto.Signer, payload []byte) error {
	var name string
	var sig []byte
	var err error
	hasher := sha256.New()
	_, _ = hasher.Write(payload)
	hashed := hasher.Sum(nil)
	switch signer.Public().(type) {
	case *rsa.PublicKey:
		name = "rsa-sha256"
		sig, err = signer.Sign(rand.Reader, hashed, crypto.SHA256)
	case ed25519.PublicKey:
		name = "ed25519-sha256"
		sig, err = signer.Sign(rand.Reader, hashed, crypto.Hash(0))
	default:
		return fmt.Errorf("dkim2: unsupported key algorithm %T", signer.Public())
	}
	if err != nil {
		return err
	}
	d.Signatures = append(d.Signatures, Sig{
		Selector:  selector,
		Name:      name,
		Signature: sig,
	})
	return nil
}

// ToString converts a signature to a folded header.
func (d *Signature) ToString() string {
	var b strings.Builder
	_, _ = fmt.Fprintf(&b, "i=%d; m=%d; t=%d; d=%s", d.Sequence, d.MIRevision, d.Timestamp, d.Domain)
	var rcptTos []string
	for _, addr := range d.RcptTo {
		rcptTos = append(rcptTos, base64.StdEncoding.EncodeToString([]byte(addr)))
	}
	_, _ = fmt.Fprintf(&b, ";\r\n mf=%s;\r\n rt=%s",
		base64.StdEncoding.EncodeToString([]byte(d.MailFrom)),
		strings.Join(rcptTos, ",\r\n "))
	if d.Nonce != "" {
		_, _ = fmt.Fprintf(&b, ";\r\n n=%s;", d.Nonce)
	}
	var sigs []string
	for _, sig := range d.Signatures {
		sigs = append(sigs, sig.String())
	}
	_, _ = fmt.Fprintf(&b, ";\r\n s=%s", strings.Join(sigs, ",\r\n "))

	allFlags := d.ExtraFlags
	if d.Exploded {
		allFlags = append(allFlags, "exploded")
	}
	if d.DoNotExplode {
		allFlags = append(allFlags, "donotexplode")
	}
	if d.DoNotModify {
		allFlags = append(allFlags, "donotmodify")
	}
	if d.Feedback {
		allFlags = append(allFlags, "feedback")
	}
	if len(allFlags) > 0 {
		_, _ = fmt.Fprintf(&b, ";\r\n f=%s", strings.Join(allFlags, ","))
	}
	return b.String()
}

func isAsciiString(s []byte) bool {
	for _, c := range s {
		if c > unicode.MaxASCII {
			return false
		}
	}
	return true
}

func isPrintString(s []byte) bool {
	for _, c := range s {
		if c > unicode.MaxASCII {
			return false
		}
		if !unicode.IsPrint(rune(c)) {
			return false
		}
	}
	return true
}

// Dkim2SignatureHeaders parses a slice of Dkim2-Signature
// headers and returns them as a list sorted by sequence (i=)
func Dkim2SignatureHeaders(headers []string) ([]*Signature, error) {
	d2Headers := make([]*Signature, len(headers))
	for i, h := range headers {
		d2, err := ParseSignature(h)
		if err != nil {
			return nil, err
		}
		d2Headers[i] = d2
	}
	slices.SortFunc(d2Headers, func(a, b *Signature) int {
		return cmp.Compare(a.Sequence, b.Sequence)
	})
	return d2Headers, nil
}
