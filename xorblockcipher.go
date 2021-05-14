package jmtcrypto

// Implementation of a basic XOR block cipher (Vigenère cipher)
// This is hopelessly insecure and shoudl not be used.
// It is only included for demonstration purposes

// XORCode - 
type XORCode struct {
	key []byte
}

// MakeXORCode - 
func MakeXORCode(key []byte) XORCode {
	return XORCode{key:key}
}

func (code XORCode) blockSize() int {
	return 16
}

func (code XORCode) blockEncrypt(w []byte) (wout []byte) {
	return byteStreamXOR(w, code.key)
}

func (code XORCode) blockDecrypt(w []byte) (wout []byte) {
	return code.blockEncrypt(w)
}