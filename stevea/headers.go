package dkim2

import (
	"bytes"
	"io"
	"net/mail"
	"regexp"
)

const (
	hdrMessageInstance = "Message-Instance"
	lwrMessageInstance = "message-instance"
	hdrDKIM2Signature  = "Dkim2-Signature"
	lwrDKIM2Signature  = "dkim2-signature"
)

var blankLineRe = regexp.MustCompile(`\n\r?\n`)

// ReadMessage reads an email from a reader and returns
// the raw headers and the mail as a mail.Message.
func ReadMessage(r io.Reader) ([]byte, *mail.Message, error) {
	var header bytes.Buffer
	t := io.TeeReader(r, &header)
	msg, err := mail.ReadMessage(t)
	if err != nil {
		return nil, nil, err
	}
	rawHeader := header.Bytes()
	eoh := blankLineRe.FindIndex(rawHeader)
	if eoh != nil {
		rawHeader = rawHeader[:eoh[0]+1]
	}
	return rawHeader, msg, nil
}
