package dkim2

import (
	"net/mail"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

/*

Message-Instance: m=1;
h=sha256: r+eDvDsRLH2RA6B/XHTZLWJ5rDoB6xqAh//Xuqzp7DU=:4M5VЗw0E9+JY04qХqLjV2r6WCKvUrlP0h9oupBC8sqw=
DKIM2-Signature: i=1; m=1; d=socketlabs.com; s=dkim: rsa-sha256:czuPJ+BxHt7rmavbihn2DuD34YE2WqXizHMzKuu8BeWeX0COmVzRbch6Wni26216I6QnIdBJenluX17IiC0gdbiWrvYZ4gl7G
mf=PGM40TAuODIuMWY0N2RkMDAwMDAwMGU30C4wNmFiZGU3ZjFmYzA3ZWFiZjUzYzk5ZTMy0Dg2ZGY4NkBzb2NrZXRsYWJzLmNvbT4=;
rt=PHRlc3RAW3JlZGFjdGVkXS5jb20+; t=1777074246
*/

func TestMessageInstance_Parse(t *testing.T) {
	tests := map[string]struct {
		Header  string
		Want    *MessageInstance
		WantErr bool
	}{
		"thankssl": {
			Header: "Message-Instance: m=1;\r\n h=sha256: r+eDvDsRLH2RA6B/XHTZLWJ5rDoB6xqAh//Xuqzp7DU=:4M5V3wOE9+JY04qXqLjV2r6WCKvUrlP0h9oupBC8sqw=\r\n",
			Want: &MessageInstance{
				Revision: 1,
				Hashes: []HashSet{
					{
						Name:       "sha256",
						HeaderHash: []byte{0xaf, 0xe7, 0x83, 0xbc, 0x3b, 0x11, 0x2c, 0x7d, 0x91, 0x3, 0xa0, 0x7f, 0x5c, 0x74, 0xd9, 0x2d, 0x62, 0x79, 0xac, 0x3a, 0x1, 0xeb, 0x1a, 0x80, 0x87, 0xff, 0xd7, 0xba, 0xac, 0xe9, 0xec, 0x35},
						BodyHash:   []byte{0xe0, 0xce, 0x55, 0xdf, 0x3, 0x84, 0xf7, 0xe2, 0x58, 0xd3, 0x8a, 0x97, 0xa8, 0xb8, 0xd5, 0xda, 0xbe, 0x96, 0x8, 0xab, 0xd4, 0xae, 0x53, 0xf4, 0x87, 0xda, 0x2e, 0xa4, 0x10, 0xbc, 0xb2, 0xac},
					},
				},
				Recipes:  nil,
				Original: "m=1; h=sha256: r+eDvDsRLH2RA6B/XHTZLWJ5rDoB6xqAh//Xuqzp7DU=:4M5V3wOE9+JY04qXqLjV2r6WCKvUrlP0h9oupBC8sqw=",
			},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			msg, err := mail.ReadMessage(strings.NewReader(tc.Header))
			if err != nil {
				t.Fatal(err)
			}
			mi, err := ParseMessageInstance(msg.Header["Message-Instance"][0])
			if (err != nil) != tc.WantErr {
				t.Errorf("expected error %v, got %v", tc.WantErr, err)
			}
			if err == nil {
				if diff := cmp.Diff(tc.Want, mi); diff != "" {
					t.Errorf("mismatch (-want +got):\n%s", diff)
				}
			}
			//t.Logf("%#v\n", mi)
		})
	}
}
