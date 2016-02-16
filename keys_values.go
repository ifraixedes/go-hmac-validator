package hmacval

type keyValueSlice []string

func (kvs keyValueSlice) Len() int {
	return int(len(kvs) / 2)
}

func (kvs keyValueSlice) Less(i int, j int) bool {
	if kvs[i*2] >= kvs[j*2] {
		return false
	}

	return true
}

func (kvs keyValueSlice) Swap(i int, j int) {
	i *= 2
	j *= 2
	kvs[j], kvs[i] = kvs[i], kvs[j]
	kvs[j+1], kvs[i+1] = kvs[i+1], kvs[j+1]
}
