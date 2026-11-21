package dkim2

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"io"
	"net/mail"
)

type SigningKey struct {
	Selector string
	Signer   crypto.Signer
}

type SignOptions struct {
	Nonce         string
	Timestamp     int64
	Domain        string
	Keys          []SigningKey
	Exploded      bool
	DoNotExplode  bool
	DoNotModify   bool
	Feedback      bool
	ExtraFlags    []string
	MailFrom      string
	RcptTo        []string
	Modifications *Recipe
	Signature     *Signature
}

func Sign(w io.Writer, r io.Reader, opts SignOptions) error {
	originalEmail, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	msg, err := mail.ReadMessage(bytes.NewReader(originalEmail))
	if err != nil {
		return err
	}
	addedHeaders, err := SignMessage(msg, opts)
	if err != nil {
		return err
	}
	for _, h := range addedHeaders {
		_, err = io.WriteString(w, h)
		if err != nil {
			return err
		}
	}
	_, err = w.Write(originalEmail)
	if err != nil {
		return err
	}
	return nil
}

// SignMessage creates DKIM2-Signature and Message-Instance headers
// that can be prepended to the provided message to sign it.
// It reads the body of the message parameter to the end.
func SignMessage(message *mail.Message,
	options SignOptions) ([]string, error) {
	var addedHeaders []string

	// Get all our existing Message-Instance headers, in ascending order
	var existingMiHeaders []*MessageInstance
	var err error
	miHeaders := message.Header[hdrMessageInstance]
	if len(miHeaders) != 0 {
		existingMiHeaders, err = MessageInstanceHeaders(miHeaders)
		if err != nil {
			return nil, err
		}
	}

	// Calculate existing hash
	hashes, err := HashMessage(message.Body, NormalizedHeaders(message.Header))
	if err != nil {
		return nil, err
	}

	// If we need a new
	var newMiHeader *MessageInstance
	if len(existingMiHeaders) == 0 {
		newMiHeader = &MessageInstance{
			Revision: 1,
			Hashes:   hashes,
			Recipes:  options.Modifications,
		}
	} else {
		newestMiHeader := existingMiHeaders[len(existingMiHeaders)-1]
		// FIXME(steve): Doesn't handle multiple hash algorithms
		if !hashes[0].ContainedBy(newestMiHeader.Hashes) {
			if options.Modifications == nil {
				return nil, ErrRequiresRecipe{}
			}
		}
		newMiHeader = &MessageInstance{
			Revision: newestMiHeader.Revision + 1,
			Hashes:   hashes,
			Recipes:  options.Modifications,
		}
	}
	if newMiHeader != nil {
		newMiString, err := newMiHeader.ToString()
		if err != nil {
			return nil, err
		}
		addedHeaders = append(addedHeaders, hdrMessageInstance+": "+newMiString+"\r\n")
		miHeaders = append(miHeaders, newMiString)
		existingMiHeaders = append(existingMiHeaders, newMiHeader)
	}

	// Create the DKIM2-Signature header we're going to
	// add signatures to.
	newSignatureHeader := options.Signature
	if newSignatureHeader == nil {
		var sigs []Sig
		for _, key := range options.Keys {
			var name string
			switch key.Signer.Public().(type) {
			case *rsa.PublicKey:
				name = "rsa-sha256"
			case ed25519.PublicKey:
				name = "ed25519-sha256"
			default:
				panic(fmt.Errorf("unsupported signing algorithm: %T", key))
			}
			sigs = append(sigs,
				Sig{
					Selector: key.Selector,
					Name:     name,
				})
		}
		newSignatureHeader = &Signature{
			Sequence:     0,
			MIRevision:   0,
			Nonce:        options.Nonce,
			Timestamp:    options.Timestamp,
			MailFrom:     options.MailFrom,
			RcptTo:       options.RcptTo,
			Domain:       options.Domain,
			Signatures:   sigs,
			Exploded:     options.Exploded,
			DoNotExplode: options.DoNotExplode,
			DoNotModify:  options.DoNotModify,
			Feedback:     options.Feedback,
			ExtraFlags:   nil,
		}
	}

	if newSignatureHeader.MIRevision == 0 {
		newestMiHeader := existingMiHeaders[len(existingMiHeaders)-1]
		newSignatureHeader.MIRevision = newestMiHeader.Revision
	}

	if newSignatureHeader.Sequence == 0 {
		d2Headers, ok := message.Header[hdrDKIM2Signature]
		if !ok {
			newSignatureHeader.Sequence = 1
		} else {
			sortedD2Headers, err := Dkim2SignatureHeaders(d2Headers)
			if err != nil {
				return nil, err
			}
			newSignatureHeader.Sequence = sortedD2Headers[len(sortedD2Headers)-1].Sequence + 1
		}
	}

	if newSignatureHeader.Timestamp == 0 {
		newSignatureHeader.Timestamp = Now()
	}

	headersToSign, err := newSignatureHeader.ConcatHeadersForSigning(mail.Header{
		hdrDKIM2Signature:  message.Header[hdrDKIM2Signature],
		hdrMessageInstance: miHeaders,
	})
	if err != nil {
		return nil, err
	}
	newSignatureHeader.Signatures = nil
	for _, signer := range options.Keys {
		err = newSignatureHeader.AddSignature(signer.Selector, signer.Signer, headersToSign)
		if err != nil {
			return nil, err
		}
	}
	addedHeaders = append(addedHeaders, hdrDKIM2Signature+": "+newSignatureHeader.ToString()+"\r\n")
	return addedHeaders, nil
}

/*
# Signer Actions

This section gives the actions that need to be undertaken by the signer
of a message. They may be done in any appropriate order.

## Add any Necessary Message-Instance Header Fields

If a system is generating the initial form of a message or if
it is a Reviser that has made changes to the message body and/or
header fields then it MUST compute the body hash as described in
{{computing-body-hash}} and the hash of the header fields
as described in {{computing-header-hash}}.

If the message does not contain a Message-Instance header field then one
MUST be added.

If hashing the message body or relevant header fields does not
give the same hash values as those recorded in the highest version
(m=) Message-Instance header field then a new Message-Instance
header field MUST be added and if they are the same a new
Message-Instance header field SHOULD NOT be added.

A Message-Instance header field MUST contain "recipes" to be able to
recreate the message corresponding to the hash values in the
currently highest numbered Message-Instance header field, or a
null recipe to indicate that recreating the previous version
of the message will not be possible.

A system may add more than one Message-Instance header field if it
wishes to do so, but the DKIM2 design allows all modifications made by
any single system to be documented
in a single Message-Instance header field.

Note that the first (m=1) Message-Instance header field MAY
contain "recipes" if it is wished to record any changes made to a
message as it enters the DKIM2 ecosystem. All other Message-Instance
header fields SHOULD contain at least one "recipe".

## Provide a "Chain of Custody" for the Message {#chain-of-custody}

The DKIM2-Signature header field contains the MAIL FROM
and RCPT TO values that will be used when the message is transmitted,
so these [RFC5321] "envelope" values MUST be available to (or
deducible by) a Signer.

The receiver of a message will check for an exact match (including
the local parts of the email addresses) between the MAIL FROM / RCPT TO
[RFC5321] protocol values and the mf= and rt= values in the highest numbered
(most recent) DKIM2-Signature header field. It is acceptable for there to
be more RCPT TO email addresses recorded in rt= than are actually used in
the SMTP conversation, but any RCPT TO value which is used MUST be present.

Verifiers will check for a relaxed domain match (see {{relaxed-domain-match}})
between the signing domain (d=) and the domain in the MAIL FROM value.

When the message being signed already has a DKIM2-Signature header field
(i.e. it has already been transmitted at least once) then a valid
"chain of custody" MUST be apparent when all of the DKIM2-Signature header fields
are considered. This "chain of custody" contributes to the way in
which DKIM2 tackles "DKIM replay" attacks.

*/
