package jmtcrypto

import (
	"errors"
	"fmt"
	"time"
)

type HashFunction interface {
	Hash(data []byte) []byte
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
		case CBC:
			cipherText = CBCEncrypt(bc, extra["iv"], msg)
		case PCB:
			cipherText = PCBCEncrypt(bc, extra["iv"], msg)
		case OFB:
			cipherText = OFBEncrypt(bc, extra["iv"], msg)
		case CTR:
			cipherText = CTREncrypt(bc, extra["nonce"], msg)
		case CFB:
			cipherText = CFBEncrypt(bc, extra["iv"], msg)
		// case PRNGSTREAM:
		// 	cipherText = ECBEncrypt(bc, msg)
	}

	cipher2 := append(cipherText, key2...)
	h := hash.Hash(cipher2)

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
	h2 := hash.Hash(cipher2)

	out := []byte{}
	var err error

	if !compareBytes(h1, h2) {
		wait(start)
		return out, errors.New("Cannot Authenticate")	
	}

	switch mode {
		case ECB:
			out, err = ECBDecrypt(bc, cipherText)
		case CBC:
			out, err = CBCDecrypt(bc, extra["iv"], cipherText)
		case PCB:
			out, err = PCBCDecrypt(bc, extra["iv"], cipherText)
		case OFB:
			out, err = OFBDecrypt(bc, extra["iv"], cipherText)
		case CTR:
			out, err = CTRDecrypt(bc, extra["nonce"], cipherText)
		case CFB:
			out, err = CFBDecrypt(bc, extra["iv"], cipherText)
		// case PRNGSTREAM:
		// 	out, err = ECBDecrypt(bc, cipherText)
	}

	if err != nil {
		wait(start)
		return out, errors.New("Cannot Authenticate")		
	}

	wait(start)
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
		case CBC:
			cipherText = CBCEncrypt(bc, extra["iv"], msg)
		case PCB:
			cipherText = PCBCEncrypt(bc, extra["iv"], msg)
		case OFB:
			cipherText = OFBEncrypt(bc, extra["iv"], msg)
		case CTR:
			cipherText = CTREncrypt(bc, extra["nonce"], msg)
		case CFB:
			cipherText = CFBEncrypt(bc, extra["iv"], msg)
		// case PRNGSTREAM:
		// 	cipherText = ECBEncrypt(bc, msg)
	}

	cipher2 := append(msg, bc.getKey()...)
	h := hash.Hash(cipher2)

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
		case CBC:
			out, err = CBCDecrypt(bc, extra["iv"], cipherText)
		case PCB:
			out, err = PCBCDecrypt(bc, extra["iv"], cipherText)
		case OFB:
			out, err = OFBDecrypt(bc, extra["iv"], cipherText)
		case CTR:
			out, err = CTRDecrypt(bc, extra["nonce"], cipherText)
		case CFB:
			out, err = CFBDecrypt(bc, extra["iv"], cipherText)
		// case PRNGSTREAM:
		// 	out, err = ECBDecrypt(bc, cipherText)
	}

	out2 := append(out, bc.getKey()...)
	h2 := hash.Hash(out2)

	if !compareBytes(h1, h2) {
		wait(start)
		return out, errors.New("Cannot Authenticate")	
	}

	if err != nil {
		wait(start)
		return out, errors.New("Cannot Authenticate")		
	}

	wait(start)
	return out, nil
}

////////////////////////////////////////////////////////////////////////////////
//
// MAC-then-Encrypt
//
func MtEEncrypt(msg []byte, bc BlockCipher, hash HashFunction,
	            mode CipherMode, extra map[string]([]byte)) []byte {

	msg2 := append(msg, bc.getKey()...)
	h := hash.Hash(msg2)

	msg3 := bytePad(append(msg, h...))

	cipherText := []byte{}
	switch mode {
		case ECB:
			cipherText = ECBEncrypt(bc, msg3)
		case CBC:
			cipherText = CBCEncrypt(bc, extra["iv"], msg3)
		case PCB:
			cipherText = PCBCEncrypt(bc, extra["iv"], msg3)
		case OFB:
			cipherText = OFBEncrypt(bc, extra["iv"], msg3)
		case CTR:
			cipherText = CTREncrypt(bc, extra["nonce"], msg3)
		case CFB:
			cipherText = CFBEncrypt(bc, extra["iv"], msg3)
		// case PRNGSTREAM:
		// 	cipherText = ECBEncrypt(bc, msg3)
	}

	return cipherText
}

func MtEDecrypt(msg []byte, bc BlockCipher, hash HashFunction,
                mode CipherMode, extra map[string]([]byte)) ([]byte, error) {
	start := time.Now()

	out := []byte{}
	var err error

	switch mode {
		case ECB:
			out, err = ECBDecrypt(bc, msg)
		case CBC:
			out, err = CBCDecrypt(bc, extra["iv"], msg)
		case PCB:
			out, err = PCBCDecrypt(bc, extra["iv"], msg)
		case OFB:
			out, err = OFBDecrypt(bc, extra["iv"], msg)
		case CTR:
			out, err = CTRDecrypt(bc, extra["nonce"],msg)
		case CFB:
			out, err = CFBDecrypt(bc, extra["iv"], msg)
		// case PRNGSTREAM:
		// 	out, err = ECBDecrypt(bc, msg)
	}

	if err != nil {
		wait(start)
		fmt.Println(out)
		return out, errors.New("Cannot Authenticate")
	}

	out, err = removePad(out)
	if err != nil {
		wait(start)
		return out, errors.New("Cannot Authenticate")
	}

	h1 := make([]byte, hash.size())
	copy(h1, out[len(out) - hash.size():])

	plainText := out[:len(out) - hash.size()]

	plainText2 := append(plainText, bc.getKey()...)
	h2 := hash.Hash(plainText2)

	if !compareBytes(h1, h2) {
		wait(start)
		return out, errors.New("Cannot Authenticate")
	}

	wait(start)
	return plainText, nil
}
