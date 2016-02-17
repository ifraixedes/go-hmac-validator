package hmacval

// DEPREATE ALL THE IMPLEMENTATION OF THIS FILE; it isn't used any more
import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKeyValueSlice_Sort(t *testing.T) {
	type expect struct {
		pairs  keyValueSlice
		result keyValueSlice
	}

	expectations := []expect{
		expect{keyValueSlice{"z", "a", "a", "z", "b", "c"}, keyValueSlice{"a", "z", "b", "c", "z", "a"}},
		expect{keyValueSlice{"aa", "zz", "a", "z", "b", "c"}, keyValueSlice{"a", "z", "aa", "zz", "b", "c"}},
		expect{keyValueSlice{"a", "zz", "a", "z", "b", "c"}, keyValueSlice{"a", "zz", "a", "z", "b", "c"}},
	}

	for _, e := range expectations {
		sort.Sort(e.pairs)
		assert.EqualValues(t, e.result, e.pairs)
	}
}
