package jmtcrypto

// SHA512 -
type SHA512 struct {
	sizeBits int
	rounds   int
	hArr     [8]uint64
	kArr     [80]uint64
}

// MakeSHA512 -
func MakeSHA512() SHA512 {
	// Initialize the hash
	hArr := [8]uint64{0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
		0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 0x510e527fade682d1,
		0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179}
	// Initialize the array of round constants
	kArr := [80]uint64{
		0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
		0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe,
		0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
		0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
		0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab,
		0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
		0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
		0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
		0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
		0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
		0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373,
		0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
		0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
		0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
		0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
		0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
	}

	return SHA512{sizeBits: 512, rounds: len(kArr), hArr: hArr, kArr: kArr}
}

// Size -
func (hC SHA512) Size() int {
	return (hC.sizeBits / 8)
}

// Hash -
func (hC SHA512) Hash(data []byte) []byte {
	size := 64
	L := make([]byte, len(data))
	copy(L, data)
	K := 1
	// temporary place holder while I check how mod behaves w/ -ve numbers
	for ; (len(data)+K+8)%128 != 0; K++ {
		//
	}

	L = append(L, 0x80)
	for i := 1; i < K; i++ {
		L = append(L, 0x00)
	}

	L = append(L, intTo8Bytes(8*len(data), true)...)
	// at this point L should be a multiple of 128 bytes (1024 bits)..
	// .. so we can step through it in chunks of 128
	for i := 0; i < len(L); i += 128 {
		chunk := L[i:(i + 128)]
		w := [80]uint64{}
		for j := 0; j < 16; j++ {
			w[j], _ = bytesToInt64(chunk[8*j:8*(j+1)], true)
		}

		for j := 16; j < hC.rounds; j++ {
			s0 := rightRotate(w[j-15], 1, size) ^ rightRotate(w[j-15], 8, size) ^ (w[j-15] >> 7)
			s1 := rightRotate(w[j-2], 19, size) ^ rightRotate(w[j-2], 61, size) ^ (w[j-2] >> 6)

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
			s1 := rightRotate(e, 14, size) ^ rightRotate(e, 18, size) ^ rightRotate(e, 41, size)
			ch := (e & f) ^ ((^e) & g)
			temp1 := h + s1 + ch + hC.kArr[j] + w[j]
			s0 := rightRotate(a, 28, size) ^ rightRotate(a, 34, size) ^ rightRotate(a, 39, size)
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
	for _, i64 := range hC.hArr {
		hashed = append(hashed, uintTo8Bytes(i64, true)...)
	}

	return hashed[:]
}
