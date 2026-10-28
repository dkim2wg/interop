package dkim2

import "testing"

// RFC 3492 Punycode, as -08 §18 needs it for U-label -> A-label.
func TestDomainToALabel(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"bücher", "xn--bcher-kva"},
		{"münchen", "xn--mnchen-3ya"},
		{"ü", "xn--tda"},
		{"日本語", "xn--wgv71a119e"},
		{"bücher.example", "xn--bcher-kva.example"},
		{"Bücher.Example", "xn--bcher-kva.example"},
		{"example.com", "example.com"},
		{"Example.COM", "example.com"},
		{"xn--bcher-kva.example", "xn--bcher-kva.example"},
	} {
		if got := toALabel(tc.in); got != tc.want {
			t.Errorf("toALabel(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestDomainOf(t *testing.T) {
	for _, tc := range []struct {
		in      string
		want    string
		literal bool
	}{
		{"<a@example.com>", "example.com", false},
		{"a@example.com", "example.com", false},
		{"<A@Example.COM.>", "example.com", false},
		{"<x@[192.0.2.1]>", "[192.0.2.1]", true},
		{"<u@bücher.example>", "xn--bcher-kva.example", false},
		{"<\"odd@local\"@example.net>", "example.net", false},
		{"<>", "", false},
		{"", "", false},
	} {
		got, lit := domainOf(tc.in)
		if got != tc.want || lit != tc.literal {
			t.Errorf("domainOf(%q) = %q,%v; want %q,%v", tc.in, got, lit, tc.want, tc.literal)
		}
	}
}

// -08 §7.2: only Parameter1 is shortened; a domain literal never matches.
func TestDomainRelaxedMatch(t *testing.T) {
	for _, tc := range []struct {
		p1, p2 string
		want   bool
	}{
		{"example.com", "example.com", true},
		{"Example.COM", "example.com", true},
		{"mail.example.org", "example.org", true},
		{"a.b.example.org", "example.org", true},
		{"example.org", "mail.example.org", false},
		{"org", "example.org", false},
		{"badexample.org", "example.org", false},
		{"[192.0.2.1]", "[192.0.2.1]", false},
		{"", "example.org", false},
		{"example.org", "", false},
	} {
		if got := relaxedMatch(tc.p1, tc.p2); got != tc.want {
			t.Errorf("relaxedMatch(%q, %q) = %v, want %v", tc.p1, tc.p2, got, tc.want)
		}
	}
}

// -08 §11: one mailbox, Name <a@b> or a@b; groups and lists fail.
func TestDomainFromMailbox(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string // "" = not exactly one usable mailbox
	}{
		{"A <a@example.com>", "a@example.com"},
		{"a@example.com", "a@example.com"},
		{" a@example.com (comment)", "a@example.com"},
		{"=?utf-8?q?Caf=C3=A9?=\r\n <a@example.com>", "a@example.com"},
		{"\"Doe, John\" <j@example.com>", "j@example.com"},
		{"a@example.com, b@example.com", ""},
		{"A <a@example.com>, B <b@example.com>", ""},
		{"group: a@example.com;", ""},
		{"undisclosed-recipients:;", ""},
		{"no address here", ""},
		{"", ""},
	} {
		got, ok := fromMailbox(tc.in)
		if !ok {
			got = ""
		}
		if got != tc.want {
			t.Errorf("fromMailbox(%q) = %q,%v; want %q", tc.in, got, ok, tc.want)
		}
	}
}
