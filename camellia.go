package jmtcrypto

import (
	"errors"
	// "math/rand"
)

var sigma1 = uint64(0xA09E667F3BCC908B)
var sigma2 = uint64(0xB67AE8584CAA73B2)
var sigma3 = uint64(0xC6EF372FE94F82BE)
var sigma4 = uint64(0x54FF53A5F1D36F1C)
var sigma5 = uint64(0x10E527FADE682D1D)
var sigma6 = uint64(0xB05688C2B3E6C1FD)

type uint128 [2]uint64


type CamelliaCode struct {
	// numberOfRounds  int
	key             []byte
}

func MakeCamellia(key []byte) CamelliaCode {
	// n := 0
	// if len(key) == 4 {
	// 	n = 11
	// } else if len(key) == 6 {
	// 	n = 13
	// } else if len(key) == 8 {
	// 	n = 15
	// }

	return CamelliaCode{key:key}
}

func (code CamelliaCode) blockSize() int {
	return 16 // 16 bytes = 128 bits
}

// 16 Bytes = 128
// 24 Bytes = 196
// 32 Bytes = 256
func (code CamelliaCode) keyExpansion() (expanded map[string]uint64) {
	n := 8 * len(code.key)
	var kl, kr uint128
	
	kl[0], _ = convert(code.key[:8])
	kl[1], _ = convert(code.key[8:16])
	switch n {
		case 128:
		case 196:
			// copy(kr[0], code.key[16:])
			kr[0], _ = convert(code.key[16:])
			kr[1] = ^kr[0]
		case 256:
			kr[0], _ = convert(code.key[16:24])
			kr[1], _ = convert(code.key[24:])
	}

	var d1, d2 uint64
	var ka, kb uint128

	d1 = kl[0] ^ kr[0]
	d2 = kl[1] ^ kr[1]
	d2 = d2 ^ f(d1, sigma1)
	d1 = d1 ^ f(d2, sigma2)
	d1 = d1 ^ kl[0]
	d2 = d2 ^ kl[1]
	d2 = d2 ^ f(d1, sigma3);
	d1 = d1 ^ f(d2, sigma4);
	ka[0] = d1
	ka[1] = d2

	d1 = ka[0] ^ kr[0]
	d2 = ka[1] ^ kr[1]
	d2 = d2 ^ f(d1, sigma5);
	d1 = d1 ^ f(d2, sigma6);

	kb[0] = d1
	kb[1] = d2	

	return
}

func insert(m map[string][8]byte, arr []byte, name string) {
	temp := [8]byte{}
	copy(temp[:], arr)
	m[name] = temp	

	return
}

func convert(arr []byte) (uint64, error) {
	if len(arr) != 8 {
		return 0, errors.New("Not 8 bytes")
	}
	value := uint64(0)
	for _, v := range arr {
		value <<= 8
		value += uint64(v)
	}

	return value, nil
}

func xor8(a, b [8]byte) (c [8]byte) {
	for i := 0; i < 8; i++ {
		c[i] = a[i] ^ b[i]
	}

	return
}

func f(f_in, ke uint64) (f_out uint64) {
	var x uint64
	var t1, t2, t3, t4, t5, t6, t7, t8  byte
	var y1, y2, y3, y4, y5, y6, y7, y8  byte
	x  = f_in ^ ke
	t1 = byte(x >> 56);
	t2 = byte(x >> 48)
	t3 = byte(x >> 40)
	t4 = byte(x >> 32)
	t5 = byte(x >> 24)
	t6 = byte(x >> 16)
	t7 = byte(x >>  8)
	t8 = byte(x >>  0)
	// t1 = SBOX1[t1];
	// t2 = SBOX2[t2];
	// t3 = SBOX3[t3];
	// t4 = SBOX4[t4];
	// t5 = SBOX2[t5];
	// t6 = SBOX3[t6];
	// t7 = SBOX4[t7];
	// t8 = SBOX1[t8];
	y1 = t1 ^ t3 ^ t4 ^ t6 ^ t7 ^ t8;
	y2 = t1 ^ t2 ^ t4 ^ t5 ^ t7 ^ t8;
	y3 = t1 ^ t2 ^ t3 ^ t5 ^ t6 ^ t8;
	y4 = t2 ^ t3 ^ t4 ^ t5 ^ t6 ^ t7;
	y5 = t1 ^ t2 ^ t6 ^ t7 ^ t8;
	y6 = t2 ^ t3 ^ t5 ^ t7 ^ t8;
	y7 = t3 ^ t4 ^ t5 ^ t6 ^ t8;
	y8 = t1 ^ t4 ^ t5 ^ t6 ^ t7;

	f_out = uint64(y1 << 56) | uint64(y2 << 48) | uint64(y3 << 40) |
	        uint64(y4 << 32) | uint64(y5 << 24) | uint64(y6 << 16) |
	        uint64(y7 <<  8) | uint64(y8);
	return f_out;
}