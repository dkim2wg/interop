package dkim2

// The Go side of util/xbench.sh, the cross-implementation verify benchmark.
// In-package so the keys can be parsed by the package's own key-record code
// from a dns.json read once (JSONKeyFetcher rereads the file per key).
// Skipped unless XB_LIST names a file of message paths.

import (
	"bufio"
	"bytes"
	"crypto"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

type xbenchKeys map[string]map[string][][2]string

func (db xbenchKeys) FetchPublicKey(selector, domain string) (crypto.PublicKey, string, error) {
	recs, ok := db[domain][selector+"._domainkey"]
	if !ok {
		return nil, "", fmt.Errorf("%w: not in dns.json", ErrKeyNotFound)
	}
	var rrs [][]string
	for _, rec := range recs {
		if strings.ToLower(rec[0]) == "txt" {
			rrs = append(rrs, []string{rec[1]})
		}
	}
	return keyFromTXTRecords(rrs, selector+"._domainkey."+domain)
}

func TestXBench(t *testing.T) {
	list, dnsf := os.Getenv("XB_LIST"), os.Getenv("XB_DNS")
	if list == "" {
		t.Skip("XB_LIST not set (see util/xbench.sh)")
	}
	reps, _ := strconv.Atoi(os.Getenv("XB_REPS"))
	var db xbenchKeys
	data, err := os.ReadFile(dnsf)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &db); err != nil {
		t.Fatal(err)
	}
	lf, err := os.Open(list)
	if err != nil {
		t.Fatal(err)
	}
	var msgs [][]byte
	sc := bufio.NewScanner(lf)
	for sc.Scan() {
		b, err := os.ReadFile(sc.Text())
		if err != nil {
			t.Fatal(err)
		}
		msgs = append(msgs, b)
	}
	for _, undo := range []bool{false, true} {
		best := time.Hour
		var v map[string]int
		for i := 0; i < reps; i++ {
			v = map[string]int{}
			start := time.Now()
			for _, m := range msgs {
				res, err := VerifyFull(bytes.NewReader(m), db, VerifyOptions{SkipTimestampCheck: true, UndoWalk: undo})
				ok := err == nil && len(res) > 0
				for _, r := range res {
					if r.Error != nil {
						ok = false
					}
				}
				if ok {
					v["pass"]++
				} else {
					v["fail"]++
				}
			}
			if d := time.Since(start); d < best {
				best = d
			}
		}
		var counts []string
		for k, n := range v {
			counts = append(counts, fmt.Sprintf("%s=%d", k, n))
		}
		sort.Strings(counts)
		walk := "plan"
		if undo {
			walk = "undo"
		}
		fmt.Printf("go %s %.3f %s\n", walk, best.Seconds(), strings.Join(counts, ","))
	}
}
