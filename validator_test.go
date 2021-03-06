package hmacval

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"hash"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMapToSlice(t *testing.T) {
	type expect struct {
		keysToExclude []string
		payload       map[string]string
		result        []string
	}

	expectations := []expect{
		{[]string{"key2", "key3"}, map[string]string{"key1": "value1", "key2": "value2", "key3": "value3"}, []string{"key1", "value1"}},
		{[]string{"key1"}, map[string]string{"key1": "value1", "key2": "value2", "key3": "value3"}, []string{"key2", "value2", "key3", "value3"}},
		{[]string{"key2", "not-exist"}, map[string]string{"key1": "value1", "key2": "value2", "key3": "value3"}, []string{"key1", "value1", "key3", "value3"}},
		{[]string{"key1", "key2", "key3"}, map[string]string{"key1": "value1", "key2": "value2", "key3": "value3"}, []string{}},
		{[]string{}, map[string]string{"key1": "value1", "key2": "value2", "key3": "value3"}, []string{"key1", "value1", "key2", "value2", "key3", "value3"}},
		{nil, map[string]string{"key1": "value1", "key2": "value2", "key3": "value3"}, []string{"key1", "value1", "key2", "value2", "key3", "value3"}},
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
	type expect struct {
		keys   []string
		values []string
		pairs  []string
		result []string
	}

	expectations := []expect{
		{
			[]string{"1", "one", "3", "three"},
			[]string{"&", " ", "*", "star"},
			[]string{"key1", "name&surname", "key2", "close to a *", "key3", "value3"},
			[]string{"keyone", "name surname", "key2", "close to a star", "keythree", "value3"},
		},
		{
			[]string{"2", "two"},
			[]string{"&", " ", "*", "star"},
			[]string{"key1", "name", "key2", "value2", "key3", "looking at a *"},
			[]string{"key1", "name", "keytwo", "value2", "key3", "looking at a star"},
		},
		{
			[]string{"2", "two"},
			[]string{"&", " ", "*", "star"},
			[]string{"key1", "name", "keytwo", "value2", "key3", "value3"},
			[]string{"key1", "name", "keytwo", "value2", "key3", "value3"},
		},
		{
			[]string{"1", "one", "one", "three"},
			[]string{"&", "*", "*", "star"},
			[]string{"key1", "name&surname", "keyone", "close to a * & *", "key3", "value3"},
			[]string{"keyone", "name*surname", "keythree", "close to a star * star", "key3", "value3"},
		},
		{
			nil,
			[]string{"&", " ", "*", "star"},
			[]string{"key1", "A *", "keytwo", "value2", "key3", "name&surname"},
			[]string{"key1", "A star", "keytwo", "value2", "key3", "name surname"},
		},
		{
			[]string{"2", "two"},
			nil,
			[]string{"key1", "A *", "key2", "value2", "key3", "name&surname"},
			[]string{"key1", "A *", "keytwo", "value2", "key3", "name&surname"},
		},
		{nil, nil, []string{"key1", "A *", "key2", "value2", "key3", "name&surname"}, []string{"key1", "A *", "key2", "value2", "key3", "name&surname"}},
	}

	for _, e := range expectations {
		makeReplacements(e.keys, e.values, e.pairs)
		assert.EqualValues(t, e.result, e.pairs, "Replacements aren't the expected ones")
	}
}

func TestJoinKeyValue(t *testing.T) {
	type expect struct {
		pairs  []string
		link   string
		result []string
	}

	expectations := []expect{
		{[]string{"key1", "value1", "key2", "value2", "key3", "value3"}, "", []string{"key1value1", "key2value2", "key3value3"}},
		{[]string{"key1", "value1", "key2", "value2", "key3", "value3"}, "=", []string{"key1=value1", "key2=value2", "key3=value3"}},
	}

	for _, e := range expectations {
		jp := joinPairs(e.pairs, e.link)
		assert.EqualValues(t, e.result, jp, "Joined key/values aren't the expected ones")
	}
}

func TestVerifyHMAC(t *testing.T) {
	type expect struct {
		hash     func() hash.Hash
		secret   string
		payload  string
		digest   string
		valid    bool
		dDecoder func(string) ([]byte, error)
	}

	b64Decoder := func(s string) ([]byte, error) {
		return base64.StdEncoding.DecodeString(s)
	}

	expectations := []expect{
		{
			sha256.New,
			"hush",
			"shop=some-shop.myshopify.com&timestamp=1337178173",
			"c2812f39f84c32c2edaded339a1388abc9829babf351b684ab797f04cd94d4c7",
			true,
			hex.DecodeString,
		},
		{
			sha1.New,
			"12345",
			"https://mycompany.com/myapp.php?foo=1&bar=2CallSidCA1234567890ABCDECaller+14158675309Digits1234From+14158675309To+18005551212",
			"RSOYDt4T1cUTdK1PDd93/VVr8B8=",
			true,
			b64Decoder,
		},
		{
			sha1.New,
			"wrong-secret",
			"https://mycompany.com/myapp.php?foo=1&bar=2CallSidCA1234567890ABCDECaller+14158675309Digits1234From+14158675309To+18005551212",
			"RSOYDt4T1cUTdK1PDd93/VVr8B8=",
			false,
			b64Decoder,
		},
		{
			sha1.New,
			"wrong-secret",
			"https://mycompany.com/myapp.php?foo=1&bar=2CallSidCA1234567890ABCDECaller+14158675309Digits1234From+14158675309To+18005551212",
			"RSOYDt4T1cUTdK1PDd93/VVr8B8=",
			false,
			b64Decoder,
		},
	}

	for _, e := range expectations {
		digest, err := e.dDecoder(e.digest)
		require.NoError(t, err)
		v := verifyHMAC(e.hash, e.secret, e.payload, digest)
		assert.Equal(t, e.valid, v, "HMAC verification failed")
	}
}
