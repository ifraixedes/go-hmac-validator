package hmacval_test

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"hash"
	"testing"

	"github.com/ifraixedes/go-hmac-validator"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVal(t *testing.T) {
	type expect struct {
		h       func() hash.Hash
		kexc    []string
		krepl   []string
		vrepl   []string
		kvlink  string
		plink   string
		secret  string
		payload map[string]string
		hmac    string
		valid   bool
	}

	expectations := []expect{
		{
			sha256.New,
			nil,
			nil,
			nil,
			"",
			"",
			"secret",
			map[string]string{"key1": "value1", "key2": "value2"},
			"4d240c02738deb03be1b80361fef9c7c9ebb4db345d798946d9c5005e858dc4e",
			true,
		},
		{
			sha256.New,
			nil,
			nil,
			nil,
			"=",
			"",
			"secret",
			map[string]string{"key1": "value1", "key2": "value2"},
			"8177695f5c7227910968d795d458a2d131318cf0dd763b8e03a3767f6e80dbaf",
			true,
		},
		{
			sha256.New,
			nil,
			nil,
			nil,
			"=",
			"&",
			"secret",
			map[string]string{"key1": "value1", "key2": "value2"},
			"59e0a47b8cb0220207101a844200073d87dccf3611ac230a56fab07352109b95",
			true,
		},
		{
			sha256.New,
			[]string{"key2"},
			nil,
			nil,
			"=",
			"&",
			"secret",
			map[string]string{"key1": "value1", "key2": "value2"},
			"b7ccb53c1546eadd654ff633972d841347669b25fbc6a945f79a654ba6b265fe",
			true,
		},
		{
			sha256.New,
			[]string{"key3"},
			[]string{"1", "one"},
			[]string{"2", "two"},
			"=",
			"&",
			"secret",
			map[string]string{"key1": "value1", "key2": "value2", "key3": "value3"},
			"c1828816eac7fa67fbe3847bf4cab5ecfd93b83fe1fc419044c930e237b0e9d2",
			true,
		},
		{
			sha256.New,
			[]string{"key3"},
			[]string{"1", "one"},
			[]string{"2", "two"},
			"=",
			"&",
			"invaid-secret",
			map[string]string{"key1": "value1", "key2": "value2", "key3": "value3"},
			"c1828816eac7fa67fbe3847bf4cab5ecfd93b83fe1fc419044c930e237b0e9d2",
			false,
		},
	}

	for i, e := range expectations {
		dmac, err := hex.DecodeString(e.hmac)
		require.NoError(t, err)
		val := hmacval.NewVal(e.h, e.kexc, e.krepl, e.vrepl, e.kvlink, e.plink)
		assert.Equal(t, e.valid, val(e.secret, "", e.payload, dmac), "HMAC validation result hasn't matched the result of expectation %d", i)
	}
}

func TestShopifyAuthSignature(t *testing.T) {
	payload := map[string]string{"shop&name": "some%shop&myshopify", "ts=timestamp": "0123456789", "signature": "6e39a2ea9e497af6cb806720da1f1bf3", "hmac": "b0fe5821780f72f903b23199fc80ef888831cb10dbb7ee9b2182ad2066cedc4c"}
	dmac, err := hex.DecodeString("b0fe5821780f72f903b23199fc80ef888831cb10dbb7ee9b2182ad2066cedc4c")
	require.NoError(t, err)
	val := hmacval.NewVal(
		sha256.New,
		[]string{"signature", "hmac"},
		[]string{"&", "%26", "%", "%25", "=", "%3D"},
		[]string{"&", "%26", "%", "%25"},
		"=",
		"&")
	assert.Equal(t, true, val("secret", "", payload, dmac), "HMAC validation should be true")

}

func TestTwilioAuthSignature(t *testing.T) {
	payload := map[string]string{"CallSid": "CA1234567890ABCDE", "Caller": "+14158675309", "Digits": "1234", "From": "+14158675309", "To": "+18005551212"}
	dmac, err := base64.StdEncoding.DecodeString("RSOYDt4T1cUTdK1PDd93/VVr8B8=")
	require.NoError(t, err)
	val := hmacval.NewVal(sha1.New, nil, nil, nil, "", "")
	assert.Equal(t, true, val("12345", "https://mycompany.com/myapp.php?foo=1&bar=2", payload, dmac), "HMAC validation should be true")
}

func TestPusherAuthSignature(t *testing.T) {
	dmac, err := hex.DecodeString("afaed3695da2ffd16931f457e338e6c9f2921fa133ce7dac49f529792be6304c")
	require.NoError(t, err)
	val := hmacval.NewVal(sha256.New, nil, nil, nil, "", "")
	assert.Equal(t, true, val("7ad3773142a6692b25b8", "1234.1234:presence-foobar:{\"user_id\":10,\"user_info\":{\"name\":\"Mr. Pusher\"}}", nil, dmac), "HMAC validation should be true")
}
