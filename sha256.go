package jmtcrypto

type SHA256 struct {
	sizeBits int
}

func MakeSHA256() SHA256 {
	return SHA256{sizeBits:256}
}

func (h SHA256) size() int {
	return (h.sizeBits / 8)
}

func (h SHA256) hash(data []byte) []byte {
	for ; len(data) < h.size(); {
		data = append(data, data...)
	}

	return data[:h.size()]
}
