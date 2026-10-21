package dkim2

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeResolver answers TXT lookups from dns.json.  behave picks, per name
// and per call (1 = the first lookup of that name), what to do instead:
// "ok", "nxdomain", "servfail", "timeout" or "hang" (block until release
// is closed, then answer).
type fakeResolver struct {
	mu      sync.Mutex
	db      map[string][]string
	calls   map[string]int
	behave  func(name string, call int) string
	release chan struct{}
	seen    chan string
}

func newFakeResolver(t *testing.T, behave func(string, int) string) *fakeResolver {
	t.Helper()
	data, err := os.ReadFile("../../dns.json")
	if err != nil {
		t.Fatal(err)
	}
	var db map[string]map[string][][2]string
	if err := json.Unmarshal(data, &db); err != nil {
		t.Fatal(err)
	}
	r := &fakeResolver{db: map[string][]string{}, calls: map[string]int{},
		behave: behave, release: make(chan struct{}), seen: make(chan string, 100)}
	for dom, recs := range db {
		for sel, rrs := range recs {
			for _, rr := range rrs {
				if rr[0] == "txt" {
					r.db[sel+"."+dom] = append(r.db[sel+"."+dom], rr[1])
				}
			}
		}
	}
	t.Cleanup(func() { close(r.release) })
	return r
}

func (r *fakeResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	r.mu.Lock()
	r.calls[name]++
	call := r.calls[name]
	r.mu.Unlock()
	r.seen <- name
	b := "ok"
	if r.behave != nil {
		b = r.behave(name, call)
	}
	switch b {
	case "nxdomain":
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	case "servfail":
		return nil, &net.DNSError{Err: "server misbehaving", Name: name, IsTemporary: true}
	case "timeout":
		return nil, &net.DNSError{Err: "i/o timeout", Name: name, IsTimeout: true, IsTemporary: true}
	case "hang":
		<-r.release
	}
	txts, ok := r.db[name]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
	return txts, nil
}

func (r *fakeResolver) count() map[string]int {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := map[string]int{}
	for k, v := range r.calls {
		out[k] = v
	}
	return out
}

// prefetchMsg is a two-hop chain whose keys are under two names.
func prefetchMsg(t *testing.T) ([]byte, []string) {
	_, msg := buildDoubleSignedMsg(t)
	return msg, []string{"ed25519._domainkey.test1.dkim2.com", "ed25519._domainkey.test2.dkim2.com"}
}

// verifyWith verifies msg with a NetKeyFetcher on res, prefetching or not.
func verifyWith(msg []byte, res TXTResolver, prefetch bool) string {
	opt := VerifyOptions{SkipTimestampCheck: true, NoKeyPrefetch: !prefetch}
	return verdict(VerifyFull(bytes.NewReader(msg), &NetKeyFetcher{Resolver: res}, opt))
}

// TestPrefetchBeforeBody: every key is asked for once the header fields are
// in, before any of the body has arrived; a good answer is never asked
// for again.
func TestPrefetchBeforeBody(t *testing.T) {
	msg, names := prefetchMsg(t)
	res := newFakeResolver(t, nil)
	cut := bytes.Index(msg, []byte("\r\n\r\n")) + 4
	pr, pw := io.Pipe()
	done := make(chan string)
	go func() {
		done <- verdict(VerifyFull(pr, &NetKeyFetcher{Resolver: res}, VerifyOptions{SkipTimestampCheck: true}))
	}()
	pw.Write(msg[:cut])
	var got []string
	for range names {
		select {
		case n := <-res.seen:
			got = append(got, n)
		case <-time.After(10 * time.Second):
			t.Fatalf("keys not requested at the end of the header; saw %v", got)
		}
	}
	sort.Strings(got)
	if strings.Join(got, " ") != strings.Join(names, " ") {
		t.Errorf("prefetched %v, want %v", got, names)
	}
	pw.Write(msg[cut:])
	pw.Close()
	if v := <-done; strings.Contains(v, "err=<nil>") == false || strings.Contains(v, "ERROR") {
		t.Errorf("verdict:\n%s", v)
	}
	for _, n := range names {
		if c := res.count()[n]; c != 1 {
			t.Errorf("%s looked up %d times, want 1", n, c)
		}
	}
}

// TestPrefetchFallsBack: an answer that does not settle the key (a timeout,
// SERVFAIL, or nothing yet when the five seconds are up) is looked up again
// the ordinary way, and the verdict is the one the ordinary lookup gives.
func TestPrefetchFallsBack(t *testing.T) {
	defer func(d time.Duration) { keyPrefetchTimeout = d }(keyPrefetchTimeout)
	keyPrefetchTimeout = 50 * time.Millisecond
	msg, names := prefetchMsg(t)
	for _, b := range []string{"timeout", "servfail", "hang"} {
		// The prefetch fails; the ordinary lookup then works.
		res := newFakeResolver(t, func(_ string, call int) string {
			if call == 1 {
				return b
			}
			return "ok"
		})
		got := verifyWith(msg, res, true)
		want := verifyWith(msg, newFakeResolver(t, nil), false)
		if got != want {
			t.Errorf("%s: verdict\n%s\nwant\n%s", b, got, want)
		}
		for _, n := range names {
			if c := res.count()[n]; c != 2 {
				t.Errorf("%s: %s looked up %d times, want 2", b, n, c)
			}
		}
		// Every lookup fails: the TEMPERROR is the ordinary one, word for word.
		always := func(string, int) string {
			if b == "hang" {
				return "timeout"
			}
			return b
		}
		got = verifyWith(msg, newFakeResolver(t, always), true)
		want = verifyWith(msg, newFakeResolver(t, always), false)
		if got != want || !strings.Contains(got, "TEMPERROR") {
			t.Errorf("%s always: verdict\n%s\nwant\n%s", b, got, want)
		}
	}
}

// TestPrefetchNXDOMAIN: a definitive "no such name" is used as it stands.
func TestPrefetchNXDOMAIN(t *testing.T) {
	msg, names := prefetchMsg(t)
	res := newFakeResolver(t, func(_ string, call int) string {
		if call == 1 {
			return "nxdomain"
		}
		return "ok"
	})
	got := verifyWith(msg, res, true)
	if !strings.Contains(got, "public key ed25519 does not exist") {
		t.Errorf("verdict:\n%s", got)
	}
	nx := newFakeResolver(t, func(string, int) string { return "nxdomain" })
	if want := verifyWith(msg, nx, false); got != want {
		t.Errorf("verdict\n%s\nwant\n%s", got, want)
	}
	for _, n := range names {
		if c := res.count()[n]; c != 1 {
			t.Errorf("%s looked up %d times, want 1", n, c)
		}
	}
}

// TestNoPrefetchWithOverrideKeys: keys from dns.json (or any KeyFetcher
// other than real DNS), or with prefetch turned off, are not prefetched.
func TestNoPrefetchWithOverrideKeys(t *testing.T) {
	msg, _ := prefetchMsg(t)
	headers, _ := splitMessage(t, msg)
	cs, err := chainOf(headers)
	if err != nil {
		t.Fatal(err)
	}
	sigs := cs.sigs
	jf := &JSONKeyFetcher{Path: "../../dns.json"}
	if f := prefetchKeys(sigs, jf, VerifyOptions{}); f != KeyFetcher(jf) {
		t.Errorf("dns.json keys were wrapped for prefetch: %T", f)
	}
	fk := loadFileKeys(t, "../../dns.json")
	if f := prefetchKeys(sigs, fk, VerifyOptions{}); f == nil {
		t.Error("nil fetcher")
	} else if _, ok := f.(*keyPrefetcher); ok {
		t.Error("an override fetcher was prefetched")
	}
	res := newFakeResolver(t, nil)
	nf := &NetKeyFetcher{Resolver: res}
	if f := prefetchKeys(sigs, nf, VerifyOptions{NoKeyPrefetch: true}); f != KeyFetcher(nf) {
		t.Errorf("NoKeyPrefetch still prefetched: %T", f)
	}
	if len(res.count()) != 0 {
		t.Errorf("lookups made: %v", res.count())
	}
	if f := prefetchKeys(sigs, nf, VerifyOptions{}); f == KeyFetcher(nf) {
		t.Error("real DNS keys were not prefetched")
	}
}

// TestPrefetchCap: at most PrefetchMax lookups, the top signature's keys
// first, each name once, and none for an algorithm this build lacks.
func TestPrefetchCap(t *testing.T) {
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	sig := func(i int, d string, items []string) string {
		return fmt.Sprintf("DKIM2-Signature: i=%d; m=1; t=1; d=%s; mf=%s; rt=%s; s=%s\r\n",
			i, d, b64("<a@"+d+">"), b64("<b@x.example>"), strings.Join(items, ","))
	}
	items := []string{"u:new-alg:AAAA", "s0:ed25519-sha256:AAAA"}
	for k := 0; k < 50; k++ {
		items = append(items, fmt.Sprintf("s%d:rsa-sha256:AAAA", k))
	}
	sigs := []string{sig(1, "low.example", []string{"l:rsa-sha256:AAAA"}), sig(2, "top.example", items)}
	res := newFakeResolver(t, nil)
	pf, ok := prefetchKeys(sigs, &NetKeyFetcher{Resolver: res}).(*keyPrefetcher)
	if !ok {
		t.Fatal("not prefetched")
	}
	var got []string
	for name := range pf.lookups {
		got = append(got, name)
	}
	sort.Strings(got)
	want := []string{"s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7"}
	for k := range want {
		want[k] += "._domainkey.top.example"
	}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("prefetched %v, want %v", got, want)
	}
}

// TestNoPrefetchOnStructureError: a chain whose structure fails (C9 steps
// a..h) is rejected before any key is looked up.
func TestNoPrefetchOnStructureError(t *testing.T) {
	msg, _ := prefetchMsg(t)
	msg = append([]byte("DKIM2-Signature: i=5; m=1\r\n"), msg...)
	res := newFakeResolver(t, nil)
	for _, undo := range []bool{false, true} {
		_, err := VerifyFull(bytes.NewReader(msg), &NetKeyFetcher{Resolver: res},
			VerifyOptions{SkipTimestampCheck: true, UndoWalk: undo})
		if err == nil || err.Error() != "PERMERROR: DKIM2-Signature i=3 missing" {
			t.Errorf("undo=%v: err = %v", undo, err)
		}
	}
	if _, err := Verify(bytes.NewReader(msg), &NetKeyFetcher{Resolver: res}); err == nil {
		t.Error("Verify passed")
	}
	if n := res.count(); len(n) != 0 {
		t.Errorf("lookups made: %v", n)
	}
}
