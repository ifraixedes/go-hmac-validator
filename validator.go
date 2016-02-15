package hmacval

import "errors"

/*

Process to validate an HMAC digest signature:

Take map with string type keys and values (I'll call it 'payload' onwards)
 1. If HMAC digest is inside of the payload then extract it and exclude it from the HMAC signature - DONE (hmacSigValue func)!
 2. Exclude keys which shouldn't be considered to perform the HMAC signature - DONE (mapToSlice func)!
 3. Performs character replacement on the payload keys, values or both
 4. Sort the payload key/values lexicographically
 5. Join the payload Keys and its values with a specified string or none
 6. Join the payload Keys/values pairs with a specific string or none
 7. Compute the digest on the payload with the specified secret and required encoding
 8. Compare the resulted digest with the provided one (in the payload or aside) and returns if it matches or not.
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
// k make replacement on keys (odd idexes of pairs) and v on values (even indexes of pairs).
func makeReplacements(k []string, v []string, pairs []string) {
}
