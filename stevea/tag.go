package dkim2

import (
	"fmt"
	"strconv"
	"strings"
)

type TagValue struct {
	Name         string
	Value        string
	OriginalName string
}

type Tags struct {
	Tags []TagValue
}

// NewTags returns the semicolon separated key=value fields from
// an email header.
func NewTags(name string, h string, idxTag string) (Tags, error) {
	var tags []TagValue
	h = strings.ReplaceAll(h, "\r\n", "")
	for kv := range strings.SplitAfterSeq(h, ";") {
		k, v, found := strings.Cut(kv, "=")
		if !found {
			if strings.TrimSpace(kv) == "" {
				continue
			}
			return Tags{}, ErrMalformedHeader{
				Name: name,
				V:    h,
				Err:  fmt.Errorf("missing '=' in %q", kv),
				Idx:  idxForError(tags, h, idxTag),
			}
		}
		k = strings.TrimSpace(k)
		var trailingSemicolon bool
		v, trailingSemicolon = strings.CutSuffix(v, ";")
		_ = trailingSemicolon
		v = strings.TrimSpace(v)
		tags = append(tags, TagValue{
			Name:         strings.ToLower(k),
			Value:        v,
			OriginalName: k,
		})
	}
	return Tags{Tags: tags}, nil
}

func (t *Tags) Get(name string) (string, bool) {
	name = strings.ToLower(name)
	for _, tag := range t.Tags {
		if tag.Name == name {
			return tag.Value, true
		}
	}
	return "", false
}

func (t *Tags) Set(name string, value string) {
	lowerName := strings.ToLower(name)
	for i, tag := range t.Tags {
		if tag.Name == lowerName {
			t.Tags[i].Value = value
			return
		}
	}
	t.Tags = append(t.Tags, TagValue{
		Name:         lowerName,
		Value:        value,
		OriginalName: name,
	})
}

func (t *Tags) String() string {
	builder := strings.Builder{}
	for _, tag := range t.Tags {
		builder.WriteString(tag.Name)
		builder.WriteRune('=')
		builder.WriteString(tag.Value)
		builder.WriteString("; ")
	}
	return builder.String()
}

// idxForError retrieves the m= or i= field for use
// during error reporting. As we're reporting an error
// the header is likely to be malformed, so we do our
// best. Slow path.
func idxForError(tags []TagValue, h, tagName string) int {
	if tagName == "" {
		return 0
	}

	for _, tag := range tags {
		if tag.Name == tagName {
			idx, err := strconv.ParseInt(tag.Value, 10, 32)
			if err == nil {
				return int(idx)
			}
		}
	}

	for _, kv := range strings.Split(h, ";") {
		k, v, found := strings.Cut(kv, "=")
		if found && strings.ToLower(strings.TrimSpace(k)) == tagName {
			idx, err := strconv.ParseInt(v, 10, 32)
			if err == nil {
				return int(idx)
			}
		}
	}
	return 0
}

/*
func SortedTagHeaders(name string, headers []string, sortBy string) ([]Tags, error) {
	result := make(map[int]Tags, len(headers))
	for _, h := range headers {
		tags, err := NewTags(name, h)
		if err != nil {
			return nil, err
		}
		for _, tag := range tags.Tags {
			if tag.Name == sortBy {
				idx, err := strconv.ParseInt(tag.Value, 10, 32)
				if err != nil {
					return nil, ErrMalformedHeader{
						Name: name,
						V:    h,
						Err:  err,
					}
				}
			}
		}
	}
}
*/
