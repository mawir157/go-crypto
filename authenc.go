package jmtcrypto

import (
	"errors"
	"time"
)

type HashFunction interface {
	hash(data []byte) []byte
	size()            int
}

func compareBytes(b1, b2 []byte) bool {
	if len(b1) != len(b2) {
		return false
	}

	for i := 0; i < len(b1); i++ {
		if b1[i] != b2[i] {
			return false
		}
	}
	return true
}

func wait(start time.Time) {
	increment, _ := time.ParseDuration("1ms")
	delay, _ := time.ParseDuration("1s")
	t := time.Now()
	elapsed := t.Sub(start)
	for ; elapsed < delay; elapsed = t.Sub(start) {
		time.Sleep(increment)
		t = time.Now()
	}
}

// Enctryp-then-MAC
func EtMEncrypt(msg []byte, bc BlockCipher, hash HashFunction,
	            mode CipherMode, key2 []byte, extra map[string]([]byte)) []byte {

	cipherText := []byte{}
	switch mode {
		case ECB:
			cipherText = ECBEncrypt(bc, msg)
		case CBC:
			cipherText = ECBEncrypt(bc, msg)
		case PCB:
			cipherText = ECBEncrypt(bc, msg)
		case OFB:
			cipherText = ECBEncrypt(bc, msg)
		case CTR:
			cipherText = ECBEncrypt(bc, msg)
		case CFB:
			cipherText = ECBEncrypt(bc, msg)
		case PRNGSTREAM:
			cipherText = ECBEncrypt(bc, msg)
	}

	cipher2 := append(cipherText, key2...)
	h := hash.hash(cipher2)

	out := append(cipherText, h...)

	return out
}

func EtMDecrypt(msg []byte, bc BlockCipher, hash HashFunction,
                mode CipherMode, key2 []byte, extra map[string]([]byte)) ([]byte, error) {
	// grab the hash

	start := time.Now()

	h1 := msg[len(msg) - hash.size():]
	cipherText := msg[:len(msg) - hash.size()]

	cipher2 := append(cipherText, key2...)
	h2 := hash.hash(cipher2)

	out := []byte{}
	var err error

	if !compareBytes(h1, h2) {
		wait(start)
		return out, errors.New("Cannot Authenticate")	
	}

	switch mode {
		case ECB:
			out, err = ECBDecrypt(bc, msg)
		case CBC:
			out, err = ECBDecrypt(bc, msg)
		case PCB:
			out, err = ECBDecrypt(bc, msg)
		case OFB:
			out, err = ECBDecrypt(bc, msg)
		case CTR:
			out, err = ECBDecrypt(bc, msg)
		case CFB:
			out, err = ECBDecrypt(bc, msg)
		case PRNGSTREAM:
			out, err = ECBDecrypt(bc, msg)
	}

	if err != nil {
		wait(start)
		return out, errors.New("Cannot Authenticate")		
	}

	return out, nil
}