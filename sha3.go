package jmtcrypto

var RC = [24]uint64{
	0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
	0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
	0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
	0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
	0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
	0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
}

var rot = [25]int{
	0, 1, 62, 28, 27,
	36, 44, 6, 55, 20,
	3, 10, 43, 25, 39,
	41, 45, 15, 21, 8,
	18, 2, 61, 56, 14,
}

// SHA512 -
type SHA3 struct {
	sizeBits int
	r        int
	c        int
	rounds   int
	S        [25]uint64
}

// Make SHA3-224
func MakeSHA3_224() SHA3 {
	return SHA3{sizeBits: 224, r: 1152, c: 448, rounds: 24, S: [25]uint64{}}
}

// Make SHA3-256
func MakeSHA3_256() SHA3 {
	return SHA3{sizeBits: 256, r: 1088, c: 512, rounds: 24, S: [25]uint64{}}
}

// Make SHA3-384
func MakeSHA3_384() SHA3 {
	return SHA3{sizeBits: 384, r: 832, c: 768, rounds: 24, S: [25]uint64{}}
}

// Make SHA3-512
func MakeSHA3_512() SHA3 {
	return SHA3{sizeBits: 512, r: 576, c: 1024, rounds: 24, S: [25]uint64{}}
}

// Size -
func (hC SHA3) Size() int {
	return (hC.sizeBits / 8)
}

func (hC SHA3) ind(r, c int) int {
	return (r % 5) + 5*(c%5)
}

func (hC SHA3) keccak(A [25]uint64) [25]uint64 {
	for i := 0; i < hC.rounds; i++ {
		A = hC.round(A, RC[i])
	}
	return A
}

func (hC SHA3) round(A [25]uint64, rc uint64) [25]uint64 {
	B := make([]uint64, 25)
	C := make([]uint64, 5)
	D := make([]uint64, 5)

	// theta step
	for x := 0; x < 5; x++ {
		C[x] = A[hC.ind(x, 0)] ^ A[hC.ind(x, 1)] ^ A[hC.ind(x, 2)] ^ A[hC.ind(x, 3)] ^ A[hC.ind(x, 4)] // is this right?
	}
	for x := 0; x < 5; x++ {
		D[x] = C[(x+4)%5] ^ leftRotate(C[(x+1)%5], 1, 64)
	}
	for x := 0; x < 5; x++ {
		for y := 0; y < 5; y++ {
			A[hC.ind(x, y)] ^= D[x]
		}
	}

	// rho and pi step
	for x := 0; x < 5; x++ {
		for y := 0; y < 5; y++ {
			B[hC.ind(y, 2*x+3*y)] = leftRotate(A[hC.ind(x, y)], rot[hC.ind(x, y)], 64)
		}
	}

	// chi step
	for x := 0; x < 5; x++ {
		for y := 0; y < 5; y++ {
			A[hC.ind(x, y)] = B[hC.ind(x, y)] ^ ((^B[hC.ind(x+1, y)]) & B[hC.ind(x+2, y)])
		}
	}

	// iota step
	A[hC.ind(0, 0)] ^= rc

	return A
}

// Pad with 1000..0001 until hC.r bits long
func (hC SHA3) pad(data []byte) []uint64 {
	// k := len(data) // have k bytes = 8*k bits
	// 8k + s == 0 mod r
	K := 1
	// temporary place holder while I check how mod behaves w/ -ve numbers
	for ; (8*len(data)+K)%hC.r != 0; K++ {
		//
	}
	//need to add K bits
	// which is bk bytes
	bk := K / 8
	padded := data
	padded = append(padded, 0x06)
	for i := 1; i < bk-1; i++ {
		padded = append(padded, 0x00)
	}
	padded = append(padded, 0x80)

	if (8*len(padded))%hC.r != 0 {
		panic("SHA3 padding failed")
	}

	intArr, _ := bytesToInt64Slice(padded, false)
	return intArr
}

// Hash -
func (hC SHA3) Hash(data []byte) []byte {
	w := 64
	p := hC.pad(data)

	// Initilise state array to 0
	hC.S = [25]uint64{}

	// absorb step
	// grab hC.r/w values from padded message...
	for offset := 0; offset < len(p); offset += hC.r / w {
		for i := 0; i < hC.r/w; i++ {
			//.. write them into the state array S
			hC.S[i] ^= p[i+offset]
		}
		// Apply the Keccak function to S
		hC.S = hC.keccak(hC.S)
	}

	// squeezing phase
	out := []byte{}
	for 8*len(out) < hC.sizeBits {
		for i := 0; i < hC.r/w; i++ {
			// for _, v := range hC.S {
			bs := uint64To8Bytes(hC.S[i], false)
			out = append(out, bs...)
		}
		hC.S = hC.keccak(hC.S)
	}
	return out[:(hC.sizeBits / 8)]
}
