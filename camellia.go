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

	expanded = make(map[string]uint64)
	expanded["kw1"] = kl[0]
	expanded["kw2"] = kl[1]
	expanded["k1"]  = kb[0]
	expanded["k2"]  = kb[1]

	expanded["k3"] = rotate(kr, 15)[0]
	expanded["k4"] = rotate(kr, 15)[1]
	expanded["k5"] = rotate(ka, 15)[0]
	expanded["k6"] = rotate(ka, 15)[1]

	if n == 128 {
		expanded["ke1"] = rotate(ka, 30)[0]
		expanded["ke2"] = rotate(ka, 30)[1]

		expanded["k7"]  = rotate(kl, 45)[0]
		expanded["k8"]  = rotate(kl, 45)[1]
		expanded["k9"]  = rotate(ka, 45)[0]
		expanded["k10"] = rotate(kl, 60)[1]
		expanded["k11"] = rotate(ka, 60)[0]
		expanded["k12"] = rotate(ka, 60)[1]

		expanded["ke3"] = rotate(kl, 77)[0]
		expanded["ke4"] = rotate(kl, 77)[1]

		expanded["k13"] = rotate(kl, 94)[0]
		expanded["k14"] = rotate(kl, 94)[1]
		expanded["k15"] = rotate(ka, 94)[0]
		expanded["k16"] = rotate(ka, 94)[1]
		expanded["k17"] = rotate(kl, 111)[0]
		expanded["k18"] = rotate(kl, 111)[1]

		expanded["kw3"] = rotate(ka, 111)[0]
		expanded["kw4"] = rotate(ka, 111)[1]
	} else {
		expanded["ke1"] = rotate(kr, 30)[0]
		expanded["ke2"] = rotate(kr, 30)[1]
		expanded["k7"]  = rotate(kb, 30)[0]
		expanded["k8"]  = rotate(kb, 30)[1]
		expanded["k9"]  = rotate(kl, 45)[0]
		expanded["k10"] = rotate(kl, 45)[1]
		expanded["k11"] = rotate(ka, 45)[0]
		expanded["k12"] = rotate(ka, 45)[1]

		expanded["ke3"] = rotate(kl, 60)[0]
		expanded["ke4"] = rotate(kl, 60)[1]

		expanded["k13"] = rotate(kr, 60)[0]
		expanded["k14"] = rotate(kr, 60)[1]
		expanded["k15"] = rotate(kb, 60)[0]
		expanded["k16"] = rotate(kb, 60)[1]
		expanded["k17"] = rotate(kl, 77)[0]
		expanded["k18"] = rotate(kl, 77)[1]

		expanded["ke5"] = rotate(ka, 77)[0]
		expanded["ke6"] = rotate(ka, 77)[1]

		expanded["k19"] = rotate(kr, 94)[0]
		expanded["k20"] = rotate(kr, 94)[1]
		expanded["k21"] = rotate(ka, 94)[0]
		expanded["k22"] = rotate(ka, 94)[1]
		expanded["k23"] = rotate(kl, 111)[0]
		expanded["k24"] = rotate(kl, 111)[1]

		expanded["kw3"] = rotate(kb, 111)[0]
		expanded["kw4"] = rotate(kb, 111)[1]
	}

	return
}

func rotate(p uint128, n int) (k uint128) {
	if n >= 64 {
		k[0] = p[1]
		k[1] = p[0]

		return rotate(k, n - 64)
	} else {
		// len(l1) = len(r1) = (64 - n)
		// [l0|l1] [r0|r1] -> [l1|r0] [r1|l0]
		l0 := p[0] >> (64 - n)
		l1 := (p[0] << n)

		r0 := p[1] >> (64 - n)
		r1 := (p[1] << n)

		k[0] = l1 + r0
		k[1] = r1 + l0

		return
	}
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

func devert(v uint64) ([]byte) {
	arr := make([]byte, 8)

	for i := 0; i < 8; i++ {
		arr[7 - i] = byte(v)
		v >>= 8
	}

	return arr
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

func fl(fl_in, ke uint64) uint64 {
	var x1, x2 uint32
	var k1, k2 uint32

	x1 = uint32(fl_in >> 32)
	x2 = uint32(fl_in)

	k1 = uint32(ke >> 32)
	k2 = uint32(ke)

	temp := ((x1 & k1) >> 31) + ((x1 & k1) << 1)
	x2 = x2 ^ temp
	x1 = x1 ^ (x2 | k2)
	return (uint64(x1) << 32) + uint64(x2)
}

func flinv(flinv_in, ke uint64) uint64 {
	var y1, y2 uint32
	var k1, k2 uint32

	y1 = uint32(flinv_in >> 32)
	y2 = uint32(flinv_in)

	k1 = uint32(ke >> 32)
	k2 = uint32(ke)

	y1 = y1 ^ (y2 | k2)
	temp:= ((y1 & k1) >> 31) + ((y1 & k1) << 1)
	y2 = y2 ^ temp
	return (uint64(y1) << 32) + uint64(y2)
 }

func (code CamelliaCode) blockEncrypt(w []byte) ([]byte) {
	n := 8 * len(code.key)

	if len(w) != 16 {
		// throw error!
	}
	d1, _ := convert(w[:8]) 
	d2, _ := convert(w[8:])

	keys := code.keyExpansion()

	C := []byte{}

	if n == 128 {
		d1 = d1 ^ keys["kw1"]
		d2 = d2 ^ keys["kw2"]
		d2 = d2 ^ f(d1, keys["k1"])     // Round 1
		d1 = d1 ^ f(d2, keys["k2"])     // Round 2
		d2 = d2 ^ f(d1, keys["k3"])     // Round 3
		d1 = d1 ^ f(d2, keys["k4"])     // Round 4
		d2 = d2 ^ f(d1, keys["k5"])     // Round 5
		d1 = d1 ^ f(d2, keys["k6"])     // Round 6
		d1 = fl(d1, keys["ke1"])        // FL
		d2 = flinv(d2, keys["ke2"])     // FLINV
		d2 = d2 ^ f(d1, keys["k7"])     // Round 7
		d1 = d1 ^ f(d2, keys["k8"])     // Round 8
		d2 = d2 ^ f(d1, keys["k9"])     // Round 9
		d1 = d1 ^ f(d2, keys["k10"])    // Round 10
		d2 = d2 ^ f(d1, keys["k11"])    // Round 11
		d1 = d1 ^ f(d2, keys["k12"])    // Round 12
		d1 = fl(d1, keys["ke3"])        // FL
		d2 = flinv(d2, keys["ke4"])     // FLINV
		d2 = d2 ^ f(d1, keys["k13"])    // Round 13
		d1 = d1 ^ f(d2, keys["k14"])    // Round 14
		d2 = d2 ^ f(d1, keys["k15"])    // Round 15
		d1 = d1 ^ f(d2, keys["k16"])    // Round 16
		d2 = d2 ^ f(d1, keys["k17"])    // Round 17
		d1 = d1 ^ f(d2, keys["k18"])    // Round 18
		d2 = d2 ^ keys["kw3"]           // Postwhitening
		d1 = d1 ^ keys["kw4"]	

		C = append(C, devert(d2)...)
		C = append(C, devert(d1)...)	
	}

	return C
}


/*
   D1 = D1 ^ kw1;           // Prewhitening
   D2 = D2 ^ kw2;
   D2 = D2 ^ F(D1, k1);     // Round 1
   D1 = D1 ^ F(D2, k2);     // Round 2
   D2 = D2 ^ F(D1, k3);     // Round 3
   D1 = D1 ^ F(D2, k4);     // Round 4
   D2 = D2 ^ F(D1, k5);     // Round 5
   D1 = D1 ^ F(D2, k6);     // Round 6
   D1 = FL   (D1, ke1);     // FL
   D2 = FLINV(D2, ke2);     // FLINV
   D2 = D2 ^ F(D1, k7);     // Round 7
   D1 = D1 ^ F(D2, k8);     // Round 8
   D2 = D2 ^ F(D1, k9);     // Round 9
   D1 = D1 ^ F(D2, k10);    // Round 10
   D2 = D2 ^ F(D1, k11);    // Round 11
   D1 = D1 ^ F(D2, k12);    // Round 12
   D1 = FL   (D1, ke3);     // FL
   D2 = FLINV(D2, ke4);     // FLINV
   D2 = D2 ^ F(D1, k13);    // Round 13

Matsui, et al.               Informational                      [Page 6]
RFC 3713             Camellia Encryption Algorithm            April 2004

   D1 = D1 ^ F(D2, k14);    // Round 14
   D2 = D2 ^ F(D1, k15);    // Round 15
   D1 = D1 ^ F(D2, k16);    // Round 16
   D2 = D2 ^ F(D1, k17);    // Round 17
   D1 = D1 ^ F(D2, k18);    // Round 18
   D1 = FL   (D1, ke5);     // FL
   D2 = FLINV(D2, ke6);     // FLINV
   D2 = D2 ^ F(D1, k19);    // Round 19
   D1 = D1 ^ F(D2, k20);    // Round 20
   D2 = D2 ^ F(D1, k21);    // Round 21
   D1 = D1 ^ F(D2, k22);    // Round 22
   D2 = D2 ^ F(D1, k23);    // Round 23
   D1 = D1 ^ F(D2, k24);    // Round 24
   D2 = D2 ^ kw3;           // Postwhitening
   D1 = D1 ^ kw4;
   */