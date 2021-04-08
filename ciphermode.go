package jmtcrypto

import ()

type BlockCipher interface {
    blockEncrypt(plaintext [4]Word) [4]Word
    blockDecrypt(cipherText [4]Word) [4]Word
    blockSize() int
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
func ECBEncrypt(bc BlockCipher, msg []byte)  ([]byte) {
	out := make([]Word, 0)
	var block [4]Word
	msgW := BytesToWords(msg, true)

	for i := 0; i < len(msgW); i += 4 {
		copy(block[:], msgW[i:i+4])
		eBlock := bc.blockEncrypt(block)
		out = append(out, eBlock[:]...)
	}

	outB := WordsToBytes(out)
	return outB
}

func ECBDecrypt(bc BlockCipher, msg []byte)  ([]byte, error) {
	out := make([]Word, 0)
	var block [4]Word

	msgW := BytesToWords(msg, false)

	for i := 0; i < len(msgW); i += 4 {
		copy(block[:], msgW[i:i+4])
		eBlock := bc.blockDecrypt(block)
		out = append(out, eBlock[:]...)
	}

	outB := WordsToBytes(out)

	err := ValidatePad(outB)
	if err != nil {
    return nil, err
	}

	return outB, nil
}

////////////////////////////////////////////////////////////////////////////////
//
// Cipher block chaining (CBC)
//
func CBCEncrypt(bc BlockCipher, iv [4]Word, msg []byte)  ([]byte) {
	out := make([]Word, 0)
	var block [4]Word

	msgW := BytesToWords(msg, true)

	for i := 0; i < len(msgW); i += 4 {
		copy(block[:], msgW[i:i+4])
		for w := 0; w < 4; w++ {
			block[w] = WordXOR(block[w], iv[w])
		}
		eBlock := bc.blockEncrypt(block)
		out = append(out, eBlock[:]...)

		copy(iv[:], eBlock[:])
	}

	outB := WordsToBytes(out)

	return outB
}

func CBCDecrypt(bc BlockCipher, iv [4]Word, msg []byte)  ([]byte, error) {
	out := make([]Word, 0)
	var block [4]Word

	msgW := BytesToWords(msg, false)

	for i := 0; i < len(msgW); i += 4 {
		copy(block[:], msgW[i:i+4])
		eBlock := bc.blockDecrypt(block)

		for w := 0; w < 4; w++ {
			eBlock[w] = WordXOR(eBlock[w], iv[w])
		}
		out = append(out, eBlock[:]...)

		copy(iv[:], block[:])
	}

	outB := WordsToBytes(out)

	err := ValidatePad(outB)
	if err != nil {
    return nil, err
	}

	return outB, nil
}

////////////////////////////////////////////////////////////////////////////////
//
// Propagating cipher block chaining (PCBC)
//
func PCBCEncrypt(bc BlockCipher, iv [4]Word, msg []byte)  ([]byte) {
	out := make([]Word, 0)
	var block [4]Word

	msgW := BytesToWords(msg, true)

	for i := 0; i < len(msgW); i += 4 {
		copy(block[:], msgW[i:i+4])

		for w := 0; w < 4; w++ {
			block[w] = WordXOR(block[w], iv[w])
		}

		eBlock := bc.blockEncrypt(block)
		out = append(out, eBlock[:]...)

		for w := 0; w < 4; w++ {
			iv[w] = WordXOR(msgW[i+w], eBlock[w])
		}
	}

	outB := WordsToBytes(out)

	return outB
}

func PCBCDecrypt(bc BlockCipher, iv [4]Word, msg []byte)  ([]byte, error) {
	out := make([]Word, 0)
	var block [4]Word

	msgW := BytesToWords(msg, false)

	for i := 0; i < len(msgW); i += 4 {
		copy(block[:], msgW[i:i+4])

		eBlock := bc.blockDecrypt(block)

		for w := 0; w < 4; w++ {
			eBlock[w] = WordXOR(eBlock[w], iv[w])
		}

		out = append(out, eBlock[:]...)

		for w := 0; w < 4; w++ {
			iv[w] = WordXOR(msgW[i+w], eBlock[w])
		}
	}

	outB := WordsToBytes(out)

	err := ValidatePad(outB)
	if err != nil {
    return nil, err
	}

	return outB, nil
}

////////////////////////////////////////////////////////////////////////////////
//
// Propagating cipher block chaining (OFB)
//
func OFBEncrypt(bc BlockCipher, iv [4]Word, msg []byte)  ([]byte) {
	out := make([]Word, 0)

	msgW := BytesToWords(msg, true)

	for i := 0; i < len(msgW); i += 4 {
		eBlock := bc.blockEncrypt(iv)

		for w := 0; w < 4; w++ {
			iv[w] = eBlock[w]
		}

		for w := 0; w < 4; w++ {
			eBlock[w] = WordXOR(eBlock[w], msgW[i+w])
		}

		out = append(out, eBlock[:]...)
	}

	outB := WordsToBytes(out)

	return outB
}

func OFBDecrypt(bc BlockCipher, iv [4]Word, msg []byte)  ([]byte, error) {
	out := make([]Word, 0)

	msgW := BytesToWords(msg, false)

	for i := 0; i < len(msgW); i += 4 {
		eBlock := bc.blockEncrypt(iv)

		for w := 0; w < 4; w++ {
			iv[w] = eBlock[w]
		}

		for w := 0; w < 4; w++ {
			eBlock[w] = WordXOR(eBlock[w], msgW[i+w])
		}

		out = append(out, eBlock[:]...)
	}

	outB := WordsToBytes(out)

	err := ValidatePad(outB)
	if err != nil {
    return nil, err
	}

	return outB, nil
}

////////////////////////////////////////////////////////////////////////////////
//
// Cipher feedback (CFB)
//
func CFBEncrypt(bc BlockCipher, iv [4]Word, msg []byte)  ([]byte) {
	out := make([]Word, 0)

	msgW := BytesToWords(msg, true)

	for i := 0; i < len(msgW); i += 4 {
		eBlock := bc.blockEncrypt(iv)

		for w := 0; w < 4; w++ {
			eBlock[w] = WordXOR(eBlock[w], msgW[i+w])
		}

		for w := 0; w < 4; w++ {
			iv[w] = eBlock[w]
		}

		out = append(out, eBlock[:]...)
	}

	outB := WordsToBytes(out)

	return outB
}

func CFBDecrypt(bc BlockCipher, iv [4]Word, msg []byte)  ([]byte, error) {
	out := make([]Word, 0)

	msgW := BytesToWords(msg, false)

	for i := 0; i < len(msgW); i += 4 {
		eBlock := bc.blockEncrypt(iv)

		for w := 0; w < 4; w++ {
			eBlock[w] = WordXOR(eBlock[w], msgW[i+w])
		}

		for w := 0; w < 4; w++ {
			iv[w] = msgW[i+w]
		}

		out = append(out, eBlock[:]...)
	}

	outB := WordsToBytes(out)

	err := ValidatePad(outB)
	if err != nil {
    return nil, err
	}

	return outB, nil
}
