package jmtcrypto

// Implementation of a basic XOR block cipher (Vigenère cipher)
// This is hopelessly insecure and shoudl not be used.
// It is only included for demonstration purposes
type XORCode struct {
	key []Word
}

func MakeXORCode(key []Word) XORCode {
	return XORCode{key:key}
}

func (code XORCode) blockSize() int {
	return 16
}

func (code XORCode) blockEncrypt(w [4]Word) (wout [4]Word) {
	for i := 0; i < 4; i++ {
		wout[i] = WordXOR(w[i], code.key[i])
	}

	return
}

func (code XORCode) blockDecrypt(w [4]Word) (wout [4]Word) {
	for i := 0; i < 4; i++ {
		wout[i] = WordXOR(w[i], code.key[i])
	}

	return
}