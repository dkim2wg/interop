package dkim2

import "time"

// Now returns the current unix epoch time.
var Now = func() int64 {
	return time.Now().Unix()
}
