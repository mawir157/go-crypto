package jmtcrypto

// A block cipher that does nothing!
type NULLCode struct {
	key []byte
}

func MakeNULL(key []byte) NULLCode {
	return NULLCode{key:key}
}

func (code NULLCode) BlockSize() int {
	return 16
}

func (code NULLCode) blockEncrypt(msg []byte) ([]byte) {
	return msg
}

func (code NULLCode) blockDecrypt(msg []byte) ([]byte) {
	return msg
}

func (code NULLCode) getKey() []byte {
	return code.key
}
