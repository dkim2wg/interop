package dkim2

import (
	"io"
	"net/mail"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestReadMessage(t *testing.T) {
	tests := map[string]struct {
		Input             string
		WantRawHeader     string
		WantBody          string
		WantParsedHeaders mail.Header
		WantErr           bool
	}{
		"simple": {
			Input: "from: <steve@blighty.com>\r\n" +
				"subject: Hello World\r\n" +
				"\r\n" +
				"Body with no trailing CRLF",
			WantRawHeader: "from: <steve@blighty.com>\r\n" +
				"subject: Hello World\r\n",
			WantParsedHeaders: mail.Header{
				"From":    []string{"<steve@blighty.com>"},
				"Subject": []string{"Hello World"},
			},
			WantBody: "Body with no trailing CRLF",
			WantErr:  false,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			reader := strings.NewReader(tc.Input)
			raw, parsed, err := ReadMessage(reader)
			if (err != nil) != tc.WantErr {
				t.Errorf("error = %v, WantErr %v", err, tc.WantErr)
			}
			if err == nil {
				if diff := cmp.Diff(tc.WantRawHeader, string(raw)); diff != "" {
					t.Errorf("raw header mismatch (-want +got):\n%s", diff)
				}
				bodyRemainder, err := io.ReadAll(parsed.Body)
				if err != nil {
					t.Errorf("error reading body remainder: %v", err)
				}
				if diff := cmp.Diff(tc.WantBody, string(bodyRemainder)); diff != "" {
					t.Errorf("body mismatch (-want +got):\n%s", diff)
				}
				if diff := cmp.Diff(tc.WantParsedHeaders, parsed.Header); diff != "" {
					t.Errorf("parsed headers mismatch (-want +got):\n%s", diff)
				}

			}
		})
	}
}
