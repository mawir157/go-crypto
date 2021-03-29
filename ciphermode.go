package jmtcrypto

type blockCipher interface {
    blockEncrypt(plaintext [4]Word) [4]Word
    blockDecrypt(cipherText [4]Word) [4]Word
}

func ByteStreamXOR(bs1, bs2 []byte) (bs3 []byte) {
	bs3 = make([]byte, len(bs1))
	for i := 0; i < len(bs1); i++ {
		bs3[i] = bs1[i] ^ bs2[i]
	}

	return
}

func WordStreamXOR(bs1, bs2 []Word) (bs3 []Word) {
	bs3 = make([]Word, len(bs1))
	for i := 0; i < len(bs1); i++ {
		bs3[i] = WordXOR(bs1[i], bs2[i])
	}

	return
}

func WordXOR(w1, w2 Word) (w3 Word) {
	for i := 0; i < 4; i++ {
		w3[i] = w1[i] ^ w2[i]
	}

	return
}
////////////////////////////////////////////////////////////////////////////////
//
// Electronic Codebook (ECB)
//
func ECBEncrypt(bc blockCipher, msg []Word)  ([]Word) {
	out := make([]Word, 0)
	var block [4]Word

	for i := 0; i < len(msg); i += 4 {
		copy(block[:], msg[i:i+4])
		eBlock := bc.blockEncrypt(block)
		out = append(out, eBlock[:]...)
	}

	return out
}

func ECBDecrypt(bc blockCipher, msg []Word)  ([]Word) {
	out := make([]Word, 0)
	var block [4]Word

	for i := 0; i < len(msg); i += 4 {
		copy(block[:], msg[i:i+4])
		eBlock := bc.blockDecrypt(block)
		out = append(out, eBlock[:]...)
	}

	return out	
}

////////////////////////////////////////////////////////////////////////////////
//
// Cipher block chaining (CBC)
//
func CBCEncrypt(bc blockCipher, iv [4]Word, msg []Word)  ([]Word) {
	out := make([]Word, 0)
	var block [4]Word

	for i := 0; i < len(msg); i += 4 {
		copy(block[:], msg[i:i+4])
		for w := 0; w < 4; w++ {
			block[w] = WordXOR(block[w], iv[w])
		}
		eBlock := bc.blockEncrypt(block)
		out = append(out, eBlock[:]...)

		copy(iv[:], eBlock[:])
	}

	return out
}

func CBCDecrypt(bc blockCipher, iv [4]Word, msg []Word)  ([]Word) {
	out := make([]Word, 0)
	var block [4]Word

	for i := 0; i < len(msg); i += 4 {
		copy(block[:], msg[i:i+4])
		eBlock := bc.blockDecrypt(block)

		for w := 0; w < 4; w++ {
			eBlock[w] = WordXOR(eBlock[w], iv[w])
		}
		out = append(out, eBlock[:]...)

		copy(iv[:], block[:])
	}

	return out	
}

////////////////////////////////////////////////////////////////////////////////
//
// Propagating cipher block chaining (PCBC)
//
func PCBCEncrypt(bc blockCipher, iv [4]Word, msg []Word)  ([]Word) {
	out := make([]Word, 0)
	var block [4]Word

	for i := 0; i < len(msg); i += 4 {
		copy(block[:], msg[i:i+4])

		for w := 0; w < 4; w++ {
			block[w] = WordXOR(block[w], iv[w])
		}

		eBlock := bc.blockEncrypt(block)
		out = append(out, eBlock[:]...)

		for w := 0; w < 4; w++ {
			iv[w] = WordXOR(msg[i+w], eBlock[w])
		}
	}

	return out
}

func PCBCDecrypt(bc blockCipher, iv [4]Word, msg []Word)  ([]Word) {
	out := make([]Word, 0)
	var block [4]Word

	for i := 0; i < len(msg); i += 4 {
		copy(block[:], msg[i:i+4])

		eBlock := bc.blockDecrypt(block)

		for w := 0; w < 4; w++ {
			eBlock[w] = WordXOR(eBlock[w], iv[w])
		}

		out = append(out, eBlock[:]...)

		for w := 0; w < 4; w++ {
			iv[w] = WordXOR(msg[i+w], eBlock[w])
		}
	}

	return out
}

////////////////////////////////////////////////////////////////////////////////
//
// Propagating cipher block chaining (OFB)
//
func OFBEncrypt(bc blockCipher, iv [4]Word, msg []Word)  ([]Word) {
	out := make([]Word, 0)
	// var block [4]Word

	for i := 0; i < len(msg); i += 4 {
		eBlock := bc.blockEncrypt(iv)

		for w := 0; w < 4; w++ {
			iv[w] = eBlock[w]
		}

		for w := 0; w < 4; w++ {
			eBlock[w] = WordXOR(eBlock[w], msg[i+w])
		}

		out = append(out, eBlock[:]...)
	}

	return out
}

func OFBDecrypt(bc blockCipher, iv [4]Word, msg []Word)  ([]Word) {
	out := make([]Word, 0)
	// var block [4]Word

	for i := 0; i < len(msg); i += 4 {
		eBlock := bc.blockEncrypt(iv)

		for w := 0; w < 4; w++ {
			iv[w] = eBlock[w]
		}

		for w := 0; w < 4; w++ {
			eBlock[w] = WordXOR(eBlock[w], msg[i+w])
		}

		out = append(out, eBlock[:]...)
	}

	return out
}

////////////////////////////////////////////////////////////////////////////////
//
// Cipher feedback (CFB)
//
func CFBEncrypt(bc blockCipher, iv [4]Word, msg []Word)  ([]Word) {
	out := make([]Word, 0)

	for i := 0; i < len(msg); i += 4 {
		eBlock := bc.blockEncrypt(iv)

		for w := 0; w < 4; w++ {
			eBlock[w] = WordXOR(eBlock[w], msg[i+w])
		}

		for w := 0; w < 4; w++ {
			iv[w] = eBlock[w]
		}

		out = append(out, eBlock[:]...)
	}

	return out
}

func CFBDecrypt(bc blockCipher, iv [4]Word, msg []Word)  ([]Word) {
	out := make([]Word, 0)

	for i := 0; i < len(msg); i += 4 {
		eBlock := bc.blockEncrypt(iv)

		for w := 0; w < 4; w++ {
			eBlock[w] = WordXOR(eBlock[w], msg[i+w])
		}

		for w := 0; w < 4; w++ {
			iv[w] = msg[i+w]
		}

		out = append(out, eBlock[:]...)
	}

	return out
}
