package jmtcrypto

var state_64 = [25]uint64{
	0, 0, 0, 0, 0,
	0, 0, 0, 0, 0,
	0, 0, 0, 0, 0,
	0, 0, 0, 0, 0,
	0, 0, 0, 0, 0,
}

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
	25, 39, 3, 10, 43,
	21, 8, 41, 45, 15,
	56, 14, 18, 2, 61,
}

// SHA512 -
type SHA3 struct {
	sizeBits int
	r, c     int
	rounds   int
	S        [25]uint64
}

// Make SHA3-224
func MakeSHA3_224() SHA3 {
	return SHA3{sizeBits: 224, r: 1152, c: 448, rounds: 24, S: state_64}
}

// Make SHA3-256
func MakeSHA3_256() SHA3 {
	return SHA3{sizeBits: 256, r: 1088, c: 512, rounds: 24, S: state_64}
}

// Make SHA3-384
func MakeSHA3_384() SHA3 {
	return SHA3{sizeBits: 384, r: 832, c: 768, rounds: 24, S: state_64}
}

// Make SHA3-512
func MakeSHA3_512() SHA3 {
	return SHA3{sizeBits: 512, r: 576, c: 1024, rounds: 24, S: state_64}
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
	C := []uint64{0, 0, 0, 0, 0}
	D := []uint64{0, 0, 0, 0, 0}

	// theta step
	for x := 0; x < 5; x++ {
		C[x] = A[hC.ind(x, 0)] ^ A[hC.ind(x, 1)] ^ A[hC.ind(x, 2)] ^ A[hC.ind(x, 3)] ^ A[hC.ind(x, 3)] // is this right?
	}
	for x := 0; x < 5; x++ {
		D[x] = C[x-1] ^ rightRotate(C[x+1], 1, 64)
	}
	for x := 0; x < 5; x++ {
		for y := 0; y < 5; y++ {
			A[hC.ind(x, y)] ^= D[x]
		}
	}

	// rho and pi step
	for x := 0; x < 5; x++ {
		for y := 0; y < 5; y++ {
			B[hC.ind(y, 2*x+3*y)] = rightRotate(A[hC.ind(x, y)], rot[hC.ind(x, y)], 64)
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

// TODO
func (hC SHA3) pad(data []byte) [][25]uint64 {
	return [][25]uint64{}
}

// Hash -
func (hC SHA3) Hash(data []byte) []byte {
	w := 64
	p := hC.pad(data)

	// Initilise state
	hC.S = [25]uint64{}

	// absorb step
	for _, pi := range p {
		// pi is a [25]uint64
		// XOR the message part of pi into S
		for x := 0; x < 5; x++ {
			for y := 0; y < 5; y++ {
				if x+5*y >= hC.r/w {
					continue
				} else {
					hC.S[hC.ind(x, y)] ^= pi[hC.ind(x, y)]
				}
			}
		}
		// Apply the Keccak function to S
		hC.S = hC.keccak(hC.S)
	}

	// squeezing phase
	out := []byte{}
	for 8*len(out) < hC.sizeBits {
		for _, v := range hC.S {
			bs := uint64To16Bytes(v, true)
			out = append(out, bs...)
		}
		hC.S = hC.keccak(hC.S)
	}
	return out
}
