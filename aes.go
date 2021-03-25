package main

import (
	"fmt"
)

var sBox =
[256]byte{0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
          0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
          0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
          0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
          0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
          0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
          0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
          0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
          0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
          0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
          0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
          0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
          0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
          0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
          0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
          0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}


var sBoxInv =
[256]byte{0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
          0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
          0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
          0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
          0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
          0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
          0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
          0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
          0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
          0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
          0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
          0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
          0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
          0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
          0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
          0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d }

var rCons = [16]byte{0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
                     0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a}

type Word [4]byte // 32 bits

func PrintWord(w Word) {
	fmt.Printf("%x %x %x %x ", w[0], w[2], w[2], w[3])
}

type AESCode struct {
	numberOfRounds  int
	key             []Word
	roundCount      int
	sBox            []byte //?
}

func MakeAES(key []Word) AESCode {
	n := 0
	if len(key) == 4 {
		n = 11
	} else if len(key) == 6 {
		n = 13
	} else if len(key) == 8 {
		n = 15
	}

	return AESCode{numberOfRounds:n,
	               key:key}
}

// 128 bits = 16 Bytes
// 128 bits = 4 32 bit words
// code.key = [K0, K1, K2, K3] (16 Bytes)
// expanded = [W0, W1,..,W43] (44 words, 176 Bytes)

// 11 rounds -> 11 * (4 * Words) ->

// returns a block of 44, 52, 60 Words
func (code AESCode) keyExpansion() (expanded []Word) {
	rc := Word{0, 0, 0, 0}

	expanded = make([]Word, 4 * code.numberOfRounds)
	n := len(code.key)
	for i := 0; i < n; i++ {
		expanded[i] = code.key[i]
	}

	for i := n; i < 4 * code.numberOfRounds; i++ {
		temp := expanded[i-1]

		if (i % n == 0) {
			rc[0] = rCons[i/n]
			temp = code.xor(code.subWord(code.rotWord(temp), true), rc)
		}

		if (n == 8) && (i % n == 4) { // this can only ever be hit in 256 bit case
			temp = code.subWord(temp, true)
		}

		expanded[i] = code.xor(expanded[i - n], temp)
	}

	return
}

func (code AESCode) rotWord(word Word) (new Word) {
	new[0] = word[1]
	new[1] = word[2]
	new[2] = word[3]
	new[3] = word[0]

	return
}

// TODO
func (code AESCode) subWord(word Word, encrypt bool) (new Word) {
	for i := 0; i < 4; i++ {
		if encrypt {
			new[i] = sBox[word[i]]
		} else {
			new[i] = sBoxInv[word[i]]
		}
	}

	return
}

func (code AESCode) xor(w1, w2 Word) (w3 Word) {
	for i := 0; i < 4; i++ {
		w3[i] = w1[i] ^ w2[i]
	}

	return
}

func galMul(a, b byte) (p byte) { // Galois Field (256) Multiplication of two Bytes
	for i := 0; i < 8; i++ {
		if ((b & 1) == 1) {
			p = p ^ a
		}

		hiBitSet := (a & 0x80) != 0
		a <<= 1

		if hiBitSet {
			a = a ^ 0x1b
		}

		b >>= 1
	}
	return
}

func (code AESCode) mixColumns(w Word, encrypt bool) (new Word) {
	b := w // make a copy of w

	if encrypt {
		for i := 0; i < 4; i++ {
			h := (w[i] >> 7) & 1
			b[i] = (w[i] << 1)
			b[i] = b[i] ^ (h * 0x1b)
		}

		new[0] = b[0] ^ w[3] ^ w[2] ^ b[1] ^ w[1] /* 2 * a0 + a3 + a2 + 3 * a1 */
		new[1] = b[1] ^ w[0] ^ w[3] ^ b[2] ^ w[2] /* 2 * a1 + a0 + a3 + 3 * a2 */
		new[2] = b[2] ^ w[1] ^ w[0] ^ b[3] ^ w[3] /* 2 * a2 + a1 + a0 + 3 * a3 */
		new[3] = b[3] ^ w[2] ^ w[1] ^ b[0] ^ w[0] /* 2 * a3 + a2 + a1 + 3 * a0 */		
	} else {
		new[0] = galMul(0x0e, w[0]) ^ galMul(0x0b, w[1]) ^
		         galMul(0x0d, w[2]) ^ galMul(0x09, w[3])/* 14*a0 + 11*a1 + 13*a2 + 9*a3 */
		new[1] = galMul(0x09, w[0]) ^ galMul(0x0e, w[1]) ^
		         galMul(0x0b, w[2]) ^ galMul(0x0d, w[3])/* 9*a0 + 14*a1 + 11*a2 + 13*a3 */
		new[2] = galMul(0x0d, w[0]) ^ galMul(0x09, w[1]) ^
		         galMul(0x0e, w[2]) ^ galMul(0x0b, w[3])/* 13*a0 + 9*a1 + 14*a2 + 11*a3 */
		new[3] = galMul(0x0b, w[0]) ^ galMul(0x0d, w[1]) ^
		         galMul(0x09, w[2]) ^ galMul(0x0e, w[3])/* 11*a0 + 13*a1 + 9*a2 + 14*a3 */
	}

	return
}

func (code AESCode) shiftRow(ws [4]Word, encrypt bool) (new [4]Word) {

	if (encrypt) {
		new[0][0], new[1][0], new[2][0], new[3][0] = ws[0][0], ws[1][0], ws[2][0], ws[3][0]
		new[0][1], new[1][1], new[2][1], new[3][1] = ws[1][1], ws[2][1], ws[3][1], ws[0][1]
		new[0][2], new[1][2], new[2][2], new[3][2] = ws[2][2], ws[3][2], ws[0][2], ws[1][2]
		new[0][3], new[1][3], new[2][3], new[3][3] = ws[3][3], ws[0][3], ws[1][3], ws[2][3]
	} else {
		new[0][0], new[1][0], new[2][0], new[3][0] = ws[0][0], ws[1][0], ws[2][0], ws[3][0]
		new[0][1], new[1][1], new[2][1], new[3][1] = ws[3][1], ws[0][1], ws[1][1], ws[2][1]
		new[0][2], new[1][2], new[2][2], new[3][2] = ws[2][2], ws[3][2], ws[0][2], ws[1][2]
		new[0][3], new[1][3], new[2][3], new[3][3] = ws[1][3], ws[2][3], ws[3][3], ws[0][3]
	}
	return
}

func (code AESCode) Encrypt(msg []Word) ([]Word) {
	out := make([]Word, 0)
	var block [4]Word

	for i := 0; i < len(msg); i += 4 {
		copy(block[:], msg[i:i+4])
		eBlock := code.blockEncrypt(block)
		out = append(out, eBlock[:]...)
	}

	return out
}

// we encrypt 4 words (128 bits at a time)
func (code AESCode) blockEncrypt(w [4]Word) ([4]Word) {
	// KeyExpansion – round keys are derived from the cipher key using the AES key
	// schedule. AES requires a separate 128-bit round key block for each round
	// plus one more.
	keys := code.keyExpansion()

																						// fmt.Println("round keys")
																						// for i, k := range keys {
																						// 	fmt.Printf("%02x ", k )
																						// 	if i % 4 == 3 {
																						// 		fmt.Printf("\n")
																						// 	}
																						// }
																						// fmt.Printf("\n")

																						// fmt.Println("Plaintext")
																						// for _, b := range w {
																						// 	fmt.Printf("%02x ", b )
																						// }
																						// fmt.Printf("\n")

	// Initial round key addition:
		// AddRoundKey – each byte of the state is combined with a byte of the round
		// key using bitwise xor.
	for i := 0; i < 4; i++ {
		w[i] = code.xor(w[i], keys[i])
	}

																						// fmt.Println("After Round 0")
																						// for _, b := range w {
																						// 	fmt.Printf("%02x ", b )
																						// }
																						// fmt.Printf("\n")
																						// fmt.Printf("\n")

	// 9, 11 or 13 rounds:
	for round := 1; round < code.numberOfRounds-1; round++ {
																						// fmt.Printf("Round %d:\n", round)
																						// fmt.Printf("\tIntial word - ")
																						// for _, b := range w {
																						// 	fmt.Printf("%02x ", b )
																						// }
																						// fmt.Printf("\n")
  	// SubBytes – a non-linear substitution step where each byte is replaced
		// with another according to a lookup table.
		for j := range w {
			w[j] = code.subWord(w[j], true)
		}

																						// fmt.Printf("SubBytes\n")
																						// for _, b := range w {
																						// 	fmt.Printf("%02x ", b )
																						// }
																						// fmt.Printf("\n")

		// ShiftRows – a transposition step where the last three rows of the state
		// are shifted cyclically a certain number of steps.
		w = code.shiftRow(w, true)

																						// fmt.Printf("ShiftRows\n")
																						// for _, b := range w {
																						// 	fmt.Printf("%02x ", b )
																						// }
																						// fmt.Printf("\n")

		// MixColumns – a linear mixing operation which operates on the columns of
		// the state, combining the four bytes in each column.
		for j := 0; j < 4; j++ {
			w[j] = code.mixColumns(w[j], true)
		}

																						// fmt.Printf("MixColumns\n")
																						// for _, b := range w {
																						// 	fmt.Printf("%02x ", b )
																						// }
																						// fmt.Printf("\n")

		// AddRoundKey
		for j := 0; j < 4; j++ {
			w[j] = code.xor(w[j], keys[4*round + j])
		}

																						// fmt.Printf("AddRoundKey\n")
																						// for _, b := range w {
																						// 	fmt.Printf("%02x ", b )
																						// }
																						// fmt.Printf("\n")
																						// fmt.Printf("\n")
	}


	
																						// fmt.Printf("Final Round:\n")
																						// fmt.Printf("\tIntial word - ")
																						// for _, b := range w {
																						// 	fmt.Printf("%02x ", b )
																						// }
																						// fmt.Printf("\n")
	// Final round (making 10, 12 or 14 rounds in total):
	// SubBytes
	for j := range w {
		w[j] = code.subWord(w[j], true)
	}
																						// fmt.Printf("SubBytes\n")
																						// for _, b := range w {
																						// 	fmt.Printf("%02x ", b )
																						// }
																						// fmt.Printf("\n")
	// ShiftRows
	w = code.shiftRow(w, true)

																						// fmt.Printf("ShiftRows\n")
																						// for _, b := range w {
																						// 	fmt.Printf("%02x ", b )
																						// }
																						// fmt.Printf("\n")
	// AddRoundKey
	for j := 0; j < 4; j++ {
		w[j] = code.xor(w[j], keys[4*(code.numberOfRounds-1) + j])
	}

																						// fmt.Printf("AddRoundKey\n")
																						// for _, b := range w {
																						// 	fmt.Printf("%02x ", b )
																						// }
																						// fmt.Printf("\n")
																						// fmt.Printf("\n")

	return w	
}

func (code AESCode) Decrypt(msg []Word) ([]Word) {
	out := make([]Word, 0)
	var block [4]Word

	for i := 0; i < len(msg); i += 4 {
		copy(block[:], msg[i:i+4])
		eBlock := code.blockDecrypt(block)
		out = append(out, eBlock[:]...)
	}

	return out
}

// we run the encrypt process in reverse!
func (code AESCode) blockDecrypt(w [4]Word) ([4]Word) {
	keys := code.keyExpansion()

	// 'Final' round
	// AddRoundKey
	for j := 0; j < 4; j++ {
		w[j] = code.xor(w[j], keys[4*(code.numberOfRounds-1) + j])
	}

	// ShiftRows
	w = code.shiftRow(w, false)

	// SubBytes
	for j := range w {
		w[j] = code.subWord(w[j], false)
	}

	// for round := 1; round < code.numberOfRounds-1; round++ {
	for round := code.numberOfRounds-2; round > 0; round-- {
		// AddRoundKey
		for j := 0; j < 4; j++ {
			w[j] = code.xor(w[j], keys[4*round + j])
		}

		// MixColumns – a linear mixing operation which operates on the columns of
		// the state, combining the four bytes in each column.
		for j := 0; j < 4; j++ {
			w[j] = code.mixColumns(w[j], false)
		}

		// ShiftRows – a transposition step where the last three rows of the state
		// are shifted cyclically a certain number of steps.
		w = code.shiftRow(w, false)

		// SubBytes – a non-linear substitution step where each byte is replaced
		// with another according to a lookup table.
		for j := range w {
			w[j] = code.subWord(w[j], false)
		}
	}

	// 'Initial' round key addition:
	// AddRoundKey – each byte of the state is combined with a byte of the round
	// key using bitwise xor.
	for i := 0; i < 4; i++ {
		w[i] = code.xor(w[i], keys[i])
	}

	return w
}