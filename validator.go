package hmacval

import (
	"crypto/hmac"
	"errors"
	"fmt"
	"hash"
	"sort"
	"strings"
)

// ErrSigKeyNotFound is returned when payload doesn't contain a specified key with its own signature as a value
var ErrSigKeyNotFound = errors.New("Signature key not found in payload")

// Val is a function which compares the HMAC digest of the concatenation of the prefix (raw string which is taken without any transformation) and
// payload, using the provided secret with provided digest.
// It returns true if they match, otherwise false
type Val func(secret string, prefix string, payload map[string]string, digest []byte) bool

// Create a Val type value which will use the specified Hash algorithm, exclude the specified keys, make the specified replacements in keys
// & values, join the each key and value pair and all the pairs with the specified links.
// Replacements are expressed as pairs (odd slice positions are the strings value to be replaced by the following element in the slice)
func NewVal(h func() hash.Hash, keysToExclude []string, keyRepls []string, valueRepls []string, keyValueLink string, pairsLink string) Val {
	return Val(func(secret string, prefix string, payload map[string]string, digest []byte) bool {
		var p string

		if len(payload) > 0 {
			ps := mapToSlice(keysToExclude, payload)
			makeReplacements(keyRepls, valueRepls, ps)
			ps = joinPairs(ps, keyValueLink)
			sort.StringSlice(ps).Sort()

			if len(prefix) > 0 {
				p = fmt.Sprintf("%s%s", prefix, strings.Join(ps, pairsLink))
			} else {
				p = strings.Join(ps, pairsLink)
			}
		} else {
			p = prefix
		}

		return verifyHMAC(h, secret, p, digest)
	})
}

// mapToSlice returns a slice of key & value pairs excluding those which are in keysToExclude slice
func mapToSlice(keysToExclude []string, payload map[string]string) []string {
	result := make([]string, 0, len(payload)*2)

PayloadLoop:
	for k, v := range payload {
		if keysToExclude != nil {
			for _, e := range keysToExclude {
				if e == k {
					continue PayloadLoop
				}
			}
		}

		result = append(result, k, v)
	}

	return result
}

// makeReplacements replace the old, new string pairs of the slice of key/value pairs.
// k make replacement on keys (odd indexes of pairs) and v on values (even indexes of pairs).
// k and v can be null to represent no replacement on keys and values respectively.
func makeReplacements(k []string, v []string, pairs []string) {
	if k != nil {
		r := strings.NewReplacer(k...)

		for i := 0; i < len(pairs); i += 2 {
			pairs[i] = r.Replace(pairs[i])
		}
	}

	if v != nil {
		r := strings.NewReplacer(v...)

		for i := 1; i < len(pairs); i += 2 {
			pairs[i] = r.Replace(pairs[i])
		}
	}
}

func joinPairs(pairs []string, link string) []string {
	l := int(len(pairs) / 2)
	r := make([]string, l)

	for p := 0; p < l; p++ {
		r[p] = fmt.Sprintf("%s%s%s", pairs[p*2], link, pairs[p*2+1])
	}

	return r
}

// veiryfyHMAC generated the HMAC signature with Hash and secret and compare with the provided digest
func verifyHMAC(h func() hash.Hash, secret string, payload string, digest []byte) bool {
	hHash := hmac.New(h, []byte(secret))
	hHash.Write([]byte(payload))
	computedDigest := hHash.Sum(nil)

	return hmac.Equal(computedDigest, digest)
}
