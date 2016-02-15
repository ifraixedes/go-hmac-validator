package hmacval

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHmacSigValue(t *testing.T) {
	type expect struct {
		key     string
		payload map[string]string
		sig     string
		err     error
	}

	expectations := []expect{
		expect{"hmac", map[string]string{"key1": "value1", "key2": "value2", "hmac": "the-signature"}, "the-signature", nil},
		expect{"signature", map[string]string{"key1": "value1", "key2": "value2", "signature": "the-signature"}, "the-signature", nil},
		expect{"hmac", map[string]string{"key1": "value1", "key2": "value2", "signature": "the-signature"}, "", ErrSigKeyNotFound},
	}

	for _, e := range expectations {
		sig, err := hmacSigValue(e.key, e.payload)
		assert.Equal(t, e.sig, sig, "Sinature value doen't match")
		assert.Equal(t, e.err, err, "Returned error value doesn't match")
	}
}

func TestMapToSlice(t *testing.T) {
	type expect struct {
		keysToExclude []string
		payload       map[string]string
		result        []string
	}

	expectations := []expect{
		expect{[]string{"key2", "key3"}, map[string]string{"key1": "value1", "key2": "value2", "key3": "value3"}, []string{"key1", "value1"}},
		expect{[]string{"key1"}, map[string]string{"key1": "value1", "key2": "value2", "key3": "value3"}, []string{"key2", "value2", "key3", "value3"}},
		expect{[]string{"key2", "not-exist"}, map[string]string{"key1": "value1", "key2": "value2", "key3": "value3"}, []string{"key1", "value1", "key3", "value3"}},
		expect{[]string{"key1", "key2", "key3"}, map[string]string{"key1": "value1", "key2": "value2", "key3": "value3"}, []string{}},
		expect{[]string{}, map[string]string{"key1": "value1", "key2": "value2", "key3": "value3"}, []string{"key1", "value1", "key2", "value2", "key3", "value3"}},
		expect{nil, map[string]string{"key1": "value1", "key2": "value2", "key3": "value3"}, []string{"key1", "value1", "key2", "value2", "key3", "value3"}},
	}

	for _, e := range expectations {
		result := mapToSlice(e.keysToExclude, e.payload)
		eres := sort.StringSlice(e.result)
		res := sort.StringSlice(result)

		eres.Sort()
		res.Sort()
		assert.EqualValues(t, eres, res, "Result doesn't match the expectation")
	}
}

func TestReplaceCharacters(t *testing.T) {
	// Replace characters is possible to achieve with strings.Replacer
	t.Log("Not implemented")
	t.Skip()
}

func TestSortKeyValuePairs(t *testing.T) {
}

func TestJoinKeyValue(t *testing.T) {
	t.Log("Not implemented")
	t.Skip()
}

func TestJoinKeysValuesPairs(t *testing.T) {
	t.Log("Not implemented")
	t.Skip()
}

func TestCalcuateDigest(t *testing.T) {
	t.Log("Not implemented")
	t.Skip()
}

func TestAuthSignature_WithNoReplacements(t *testing.T) {
	t.Log("Not implemented")
	t.Skip()
}

func TestAuthSignature_WithHMACInside(t *testing.T) {
	t.Log("Not implemented")
	t.Skip()
}

func TestAuthSignature_WithHMACAside(t *testing.T) {
	t.Log("Not implemented")
	t.Skip()
}

func TestShopifyAuthSignature(t *testing.T) {
	t.Log("Not implemented")
	t.Skip()
}

func TestTwilioAuthSignature(t *testing.T) {
	t.Log("Not implemented")
	t.Skip()
}

func TestPusherthSignature(t *testing.T) {
	t.Log("Not implemented")
	t.Skip()
}
