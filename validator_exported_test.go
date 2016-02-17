package hmacval

import (
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"testing"

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
		expect{
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
		expect{
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
		expect{
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
		expect{
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
		expect{
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
		expect{
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
		val := NewVal(e.h, e.kexc, e.krepl, e.vrepl, e.kvlink, e.plink)
		assert.Equal(t, e.valid, val(e.secret, e.payload, dmac), "HMAC validation result hasn't matched the result of expectation %d", i)
	}
}

func TestShopifyAuthSignature(t *testing.T) {
	t.Log("Not implemented")
	t.Skip()
}

func TestTwilioAuthSignature(t *testing.T) {
	t.Log("Not implemented")
	t.Skip()
}

func TestPusherAuthSignature(t *testing.T) {
	t.Log("Not implemented")
	t.Skip()
}
