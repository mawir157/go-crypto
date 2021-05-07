package jmtcrypto

import (
	// "fmt"
)

type CipherMode int
const (
	ECB    CipherMode = iota
	CBC
	PCB
	OFB
	CTR
	CFB
	PRNGSTREAM
)

type BlockCipher interface {
	blockEncrypt(plaintext []byte) []byte
	blockDecrypt(cipherText []byte) []byte
	blockSize() int
	getKey() []byte
}

func byteStreamXOR(bs1, bs2 []byte) (bs3 []byte) {
	bs3 = make([]byte, len(bs1))
	for i := 0; i < len(bs1); i++ {
		bs3[i] = bs1[i] ^ bs2[i]
	}

	return
}

////////////////////////////////////////////////////////////////////////////////
//
// Electronic Codebook (ECB)
//
func ECBEncrypt(bc BlockCipher, msg []byte) ([]byte) {
	out := []byte{}

	for i := 0; i < len(msg); i += bc.blockSize() {
		eBlock := bc.blockEncrypt(msg[i:i+bc.blockSize()])
		out = append(out, eBlock...)
	}

	return out
}

func ECBDecrypt(bc BlockCipher, msg []byte) ([]byte, error) {
	out := []byte{}

	for i := 0; i < len(msg); i += bc.blockSize() {
		eBlock := bc.blockDecrypt(msg[i:i+bc.blockSize()])
		out = append(out, eBlock...)
	}

	err := ValidatePad(out)
	if err != nil {
		return nil, err
	}

	return out, nil
}

////////////////////////////////////////////////////////////////////////////////
//
// Cipher block chaining (CBC)
//
func CBCEncrypt(bc BlockCipher, iv []byte, msg []byte) ([]byte) {
	out := []byte{}

	for i := 0; i < len(msg); i += bc.blockSize() {
		block := byteStreamXOR(msg[i:i+bc.blockSize()], iv)

		eBlock := bc.blockEncrypt(block)
		out = append(out, eBlock...)

		iv = eBlock
	}

	return out
}

func CBCDecrypt(bc BlockCipher, iv []byte, msg []byte) ([]byte, error) {
	out := []byte{}

	for i := 0; i < len(msg); i += bc.blockSize() {
		eBlock := bc.blockDecrypt(msg[i:i+bc.blockSize()])

		block := byteStreamXOR(eBlock, iv)
		out = append(out, block...)

		iv = msg[i:i+bc.blockSize()]
	}

	err := ValidatePad(out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

////////////////////////////////////////////////////////////////////////////////
//
// Propagating cipher block chaining (PCBC)
//
func PCBCEncrypt(bc BlockCipher, iv []byte, msg []byte) ([]byte) {
	out := []byte{}

	for i := 0; i < len(msg); i += bc.blockSize() {
		block := byteStreamXOR(msg[i:i+bc.blockSize()], iv)

		eBlock := bc.blockEncrypt(block)
		out = append(out, eBlock...)

		iv = byteStreamXOR(msg[i:i+bc.blockSize()], eBlock)
	}

	return out
}

func PCBCDecrypt(bc BlockCipher, iv []byte, msg []byte) ([]byte, error) {
	out := []byte{}

	for i := 0; i < len(msg); i += bc.blockSize() {
		eBlock := bc.blockDecrypt(msg[i:i+bc.blockSize()])
		block := byteStreamXOR(iv, eBlock)

		out = append(out, block...)

		iv = byteStreamXOR(msg[i:i+bc.blockSize()], block)
	}

	err := ValidatePad(out)
	if err != nil {
		return nil, err
	}

	return out, nil
}

////////////////////////////////////////////////////////////////////////////////
//
// Output feedback (OFB)
//
func OFBEncrypt(bc BlockCipher, iv []byte, msg []byte) ([]byte) {
	out := []byte{}

	for i := 0; i < len(msg); i += bc.blockSize() {
		eBlock := bc.blockEncrypt(iv)

		iv = eBlock
		eBlock = byteStreamXOR(msg[i:i+bc.blockSize()], eBlock)

		out = append(out, eBlock...)
	}

	return out
}

func OFBDecrypt(bc BlockCipher, iv []byte, msg []byte) ([]byte, error) {
	out := []byte{}

	for i := 0; i < len(msg); i += bc.blockSize() {
		eBlock := bc.blockEncrypt(iv)

		iv = eBlock
		eBlock = byteStreamXOR(msg[i:i+bc.blockSize()], eBlock)

		out = append(out, eBlock...)
	}

	err := ValidatePad(out)
	if err != nil {
		return nil, err
	}

	return out, nil
}

////////////////////////////////////////////////////////////////////////////////
//
// Cipher feedback (CFB)
//
func CFBEncrypt(bc BlockCipher, iv []byte, msg []byte) ([]byte) {
	out := []byte{}

	for i := 0; i < len(msg); i += bc.blockSize() {
		eBlock := bc.blockEncrypt(iv)
		
		eBlock = byteStreamXOR(msg[i:i+bc.blockSize()], eBlock)

		iv = eBlock

		out = append(out, eBlock...)
	}

	return out
}

func CFBDecrypt(bc BlockCipher, iv []byte, msg []byte) ([]byte, error) {
	out := []byte{}

	for i := 0; i < len(msg); i += bc.blockSize() {
		eBlock := bc.blockEncrypt(iv)

		eBlock = byteStreamXOR(msg[i:i+bc.blockSize()], eBlock)

		iv = msg[i:i+bc.blockSize()]

		out = append(out, eBlock...)
	}

	err := ValidatePad(out)
	if err != nil {
		return nil, err
	}

	return out, nil
}

////////////////////////////////////////////////////////////////////////////////
//
// Counter (CTR)
//
func CTREncrypt(bc BlockCipher, nonce []byte, msg []byte) ([]byte) {
	counter := []byte{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}
	out := []byte{}

	// add extra byte to end so we can go process in blocks
	msgLen := len(msg)
	n := 16 - (msgLen % 16)
	pad := make([]byte, n)
	msg = append(msg, pad...)

	for i := 0; i < len(msg); i += bc.blockSize() {
		iv := append(nonce, counter...)

		eBlock := bc.blockEncrypt(iv)
		eBlock = byteStreamXOR(msg[i:i+bc.blockSize()], eBlock)

		out = append(out, eBlock...)

		counter = incrementCTR(counter)
	}

	return out[:msgLen]
}

func CTRDecrypt(bc BlockCipher, nonce []byte, msg []byte) ([]byte, error) {
	out := CTREncrypt(bc, nonce, msg)

	return out, nil
}

func incrementCTR(counter []byte) []byte {
	pos := 0

	counter[pos] += 1
	for counter[pos] == 0 {
		pos++
		counter[pos] += 1

		if pos > len(counter) {
			pos = len(counter) - 1
		}
	}

	return counter
}
