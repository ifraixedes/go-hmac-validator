package hmacval

import (
	"crypto/hmac"
	"errors"
	"fmt"
	"hash"
	"strings"
)

/*

Process to validate an HMAC digest signature:

Take map with string type keys and values (I'll call it 'payload' onwards)
 1. If HMAC digest is inside of the payload then extract it and exclude it from the HMAC signature - DONE! (hmacSigValue func)
 2. Exclude keys which shouldn't be considered to perform the HMAC signature - DONE! (mapToSlice func)
 3. Performs character replacement on the payload keys, values or both - DONE! individual replacement (makeReplacements), both must be added to both slices
 4. Sort the payload key/values lexicographically - DONE! (map is converted in one of the above steps in a slice of key and value pairs; this sort is done by keyValueSlice type which implement sort.Interface)
 5. Join the payload Keys and its values with a specified string or none - DONE! (joinPairs)
 6. Join the payload Keys/values pairs with a specific string or none - DONE (strings.Join does exactly this operation)
 7. Compute the digest on the payload with the specified secret and required encoding - DONE (verifyHMAC); encoding isn't needed as the encoded signature can be decoded to []byte easily with hex.DecodeString, base64.StdEncoding.DecodeString, etc.
 8. Compare the resulted digest with the provided one (in the payload or aside) and returns if it matches or not. - DONE (verifyHMAC)
*/

// ErrSigKeyNotFound is returned when payload doesn't contain a specified key with its own signature as a value
var ErrSigKeyNotFound = errors.New("Signature key not found in payload")

// hmacSignValue returns from payload, the value associated with the specified, if it exists, otherwise it returns ErrSigKeyNotFound
func hmacSigValue(key string, payload map[string]string) (string, error) {
	sig, ok := payload[key]

	if !ok {
		return "", ErrSigKeyNotFound
	}

	return sig, nil
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
