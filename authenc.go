package jmtcrypto

import (
	"errors"
	"fmt"
	"time"
)

type HashFunction interface {
	hash(data []byte) []byte
	size()            int
}

func compareBytes(b1, b2 []byte) bool {
	if len(b1) != len(b2) {
fmt.Println("a")
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

////////////////////////////////////////////////////////////////////////////////
//
// Encrypt-then-MAC
//
func EtMEncrypt(msg []byte, bc BlockCipher, hash HashFunction,
	            mode CipherMode, key2 []byte, extra map[string]([]byte)) []byte {

	cipherText := []byte{}
	switch mode {
		case ECB:
			cipherText = ECBEncrypt(bc, msg)
		// case CBC:
		// 	cipherText = ECBEncrypt(bc, msg)
		// case PCB:
		// 	cipherText = ECBEncrypt(bc, msg)
		// case OFB:
		// 	cipherText = ECBEncrypt(bc, msg)
		// case CTR:
		// 	cipherText = ECBEncrypt(bc, msg)
		// case CFB:
		// 	cipherText = ECBEncrypt(bc, msg)
		// case PRNGSTREAM:
		// 	cipherText = ECBEncrypt(bc, msg)
	}

	cipher2 := append(cipherText, key2...)
	h := hash.hash(cipher2)

	out := append(cipherText, h...)

	return out
}

func EtMDecrypt(msg []byte, bc BlockCipher, hash HashFunction,
                mode CipherMode, key2 []byte, extra map[string]([]byte)) ([]byte, error) {
	start := time.Now()

	// grab the hash
	h1 := make([]byte, hash.size())
	copy(h1,msg[len(msg) - hash.size():])

	cipherText := msg[:len(msg) - hash.size()]
	cipher2 := append(cipherText, key2...)
	h2 := hash.hash(cipher2)

	out := []byte{}
	var err error

	if !compareBytes(h1, h2) {
		wait(start)
		return out, errors.New("Cannot Authenticate 1")	
	}

	switch mode {
		case ECB:
			out, err = ECBDecrypt(bc, cipherText)
		// case CBC:
		// 	out, err = ECBDecrypt(bc, cipherText)
		// case PCB:
		// 	out, err = ECBDecrypt(bc, cipherText)
		// case OFB:
		// 	out, err = ECBDecrypt(bc, cipherText)
		// case CTR:
		// 	out, err = ECBDecrypt(bc, cipherText)
		// case CFB:
		// 	out, err = ECBDecrypt(bc, cipherText)
		// case PRNGSTREAM:
		// 	out, err = ECBDecrypt(bc, cipherText)
	}

	if err != nil {
		wait(start)
		return out, errors.New("Cannot Authenticate 2")		
	}

	return out, nil
}

////////////////////////////////////////////////////////////////////////////////
//
// Encrypt-and-MAC
//
func EaMEncrypt(msg []byte, bc BlockCipher, hash HashFunction,
	            mode CipherMode,  extra map[string]([]byte)) []byte {

	cipherText := []byte{}
	switch mode {
		case ECB:
			cipherText = ECBEncrypt(bc, msg)
		// case CBC:
		// 	cipherText = ECBEncrypt(bc, msg)
		// case PCB:
		// 	cipherText = ECBEncrypt(bc, msg)
		// case OFB:
		// 	cipherText = ECBEncrypt(bc, msg)
		// case CTR:
		// 	cipherText = ECBEncrypt(bc, msg)
		// case CFB:
		// 	cipherText = ECBEncrypt(bc, msg)
		// case PRNGSTREAM:
		// 	cipherText = ECBEncrypt(bc, msg)
	}

	cipher2 := append(msg, bc.getKey()...)
	h := hash.hash(cipher2)

	out := append(cipherText, h...)

	return out
}

func EaMDecrypt(msg []byte, bc BlockCipher, hash HashFunction,
                mode CipherMode, extra map[string]([]byte)) ([]byte, error) {
	start := time.Now()

	// grab the hash
	h1 := msg[len(msg) - hash.size():]
	cipherText := msg[:len(msg) - hash.size()]

	out := []byte{}
	var err error

	switch mode {
		case ECB:
			out, err = ECBDecrypt(bc, cipherText)
		// case CBC:
		// 	out, err = ECBDecrypt(bc, cipherText)
		// case PCB:
		// 	out, err = ECBDecrypt(bc, cipherText)
		// case OFB:
		// 	out, err = ECBDecrypt(bc, cipherText)
		// case CTR:
		// 	out, err = ECBDecrypt(bc, cipherText)
		// case CFB:
		// 	out, err = ECBDecrypt(bc, cipherText)
		// case PRNGSTREAM:
		// 	out, err = ECBDecrypt(bc, cipherText)
	}

	out2 := append(out, bc.getKey()...)
	h2 := hash.hash(out2)

	if !compareBytes(h1, h2) {
		wait(start)
		return out, errors.New("Cannot Authenticate")	
	}

	if err != nil {
		wait(start)
		return out, errors.New("Cannot Authenticate")		
	}

	return out, nil
}

////////////////////////////////////////////////////////////////////////////////
//
// MAC-then-Encrypt
//
func MtEEncrypt(msg []byte, bc BlockCipher, hash HashFunction,
	            mode CipherMode, extra map[string]([]byte)) []byte {

	cipherText := []byte{}

	msg2 := append(msg, bc.getKey()...)
	h := hash.hash(msg2)

	msg3 := append(msg, h...)

	switch mode {
		case ECB:
			cipherText = ECBEncrypt(bc, msg3)
		// case CBC:
		// 	cipherText = ECBEncrypt(bc, msg3)
		// case PCB:
		// 	cipherText = ECBEncrypt(bc, msg3)
		// case OFB:
		// 	cipherText = ECBEncrypt(bc, msg3)
		// case CTR:
		// 	cipherText = ECBEncrypt(bc, msg3)
		// case CFB:
		// 	cipherText = ECBEncrypt(bc, msg3)
		// case PRNGSTREAM:
		// 	cipherText = ECBEncrypt(bc, msg3)
	}

	return cipherText
}

func MtEDecrypt(msg []byte, bc BlockCipher, hash HashFunction,
                mode CipherMode, key2 []byte, extra map[string]([]byte)) ([]byte, error) {
	start := time.Now()

	out := []byte{}
	var err error

	switch mode {
		case ECB:
			out, err = ECBDecrypt(bc, msg)
		// case CBC:
		// 	out, err = ECBDecrypt(bc, msg)
		// case PCB:
		// 	out, err = ECBDecrypt(bc, msg)
		// case OFB:
		// 	out, err = ECBDecrypt(bc, msg)
		// case CTR:
		// 	out, err = ECBDecrypt(bc, msg)
		// case CFB:
		// 	out, err = ECBDecrypt(bc, msg)
		// case PRNGSTREAM:
		// 	out, err = ECBDecrypt(bc, msg)
	}

	if err != nil {
		wait(start)
		return out, errors.New("Cannot Authenticate")		
	}

	h1 := out[len(out) - hash.size():]
	plainText := out[:len(out) - hash.size()]

	plainText2 := append(plainText, bc.getKey()...)
	h2 := hash.hash(plainText2)

	if !compareBytes(h1, h2) {
		wait(start)
		return out, errors.New("Cannot Authenticate")	
	}

	return out, nil
}
