package jmtcrypto

// SHA256 -
type SHA256 struct {
	sizeBits int
	rounds   int
	hArr     [8]uint32
	kArr     [64]uint32
}

// MakeSHA256 -
func MakeSHA256() SHA256 {
	hArr := [8]uint32{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19}

	kArr := [64]uint32{
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
	}

	return SHA256{sizeBits: 256, rounds: len(kArr), hArr: hArr, kArr: kArr}
}

// Size -
func (hC SHA256) Size() int {
	return (hC.sizeBits / 8)
}

// Hash -
func (hC SHA256) Hash(data []byte) []byte {
	size := 32
	L := make([]byte, len(data))
	copy(L, data)
	K := 1
	// temporary place holder while I check how mod behaves w/ -ve numbers
	for ; (len(data)+K+8)%64 != 0; K++ {
		//
	}

	L = append(L, 0x80)
	for i := 1; i < K; i++ {
		L = append(L, 0x00)
	}

	L = append(L, intTo8Bytes(8*len(data), true)...)
	// at this point L should be a multiple of 64 bytes..
	// .. so we can step through it in chunks of 64
	for i := 0; i < len(L); i += 64 {
		chunk := L[i:(i + 64)]
		w := [64]uint32{}
		for j := 0; j < 16; j++ {
			w[j], _ = bytesToInt32(chunk[4*j:4*(j+1)], true)
		}

		for j := 16; j < hC.rounds; j++ {
			s0 := rightRotate(w[j-15], 7, size) ^ rightRotate(w[j-15], 18, size) ^ (w[j-15] >> 3)
			s1 := rightRotate(w[j-2], 17, size) ^ rightRotate(w[j-2], 19, size) ^ (w[j-2] >> 10)

			w[j] = w[j-16] + s0 + w[j-7] + s1
		}

		// Initialize working variables to current hash value:
		a := hC.hArr[0]
		b := hC.hArr[1]
		c := hC.hArr[2]
		d := hC.hArr[3]
		e := hC.hArr[4]
		f := hC.hArr[5]
		g := hC.hArr[6]
		h := hC.hArr[7]

		for j := 0; j < hC.rounds; j++ {
			s1 := rightRotate(e, 6, size) ^ rightRotate(e, 11, size) ^ rightRotate(e, 25, size)
			ch := (e & f) ^ ((^e) & g)
			temp1 := h + s1 + ch + hC.kArr[j] + w[j]
			s0 := rightRotate(a, 2, size) ^ rightRotate(a, 13, size) ^ rightRotate(a, 22, size)
			maj := (a & b) ^ (a & c) ^ (b & c)
			temp2 := s0 + maj

			h = g
			g = f
			f = e
			e = d + temp1
			d = c
			c = b
			b = a
			a = temp1 + temp2
		}

		// Add the compressed chunk to the current hash value:
		hC.hArr[0] += a
		hC.hArr[1] += b
		hC.hArr[2] += c
		hC.hArr[3] += d
		hC.hArr[4] += e
		hC.hArr[5] += f
		hC.hArr[6] += g
		hC.hArr[7] += h
	}
	hashed := []byte{}
	for _, i32 := range hC.hArr {
		hashed = append(hashed, intTo4Bytes(i32, true)...)
	}

	return hashed[:]
}
