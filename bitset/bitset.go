package bitset

// import (
// 	"fmt"
// )

const INTSIZE uint = 8
type Block         = []uint8

func ReverseBits(n uint8) (rev uint8) {
	for i := uint(0); i < INTSIZE; i++ {
		rev <<= 1
		if n & 1 == 1 {
			rev ^= 1
		}

		n >>= 1
  }
  return rev 
}

func InvertBits(b Block) Block {
	ones    := make(Block, len(b))
	for i := 0; i < len(b); i++ {
		ones[i]    = 255
	}

	return BlockXOR(ones, b)
}

func ParityOfBits(b Block) (out bool) {
	out = false
	for _, i8 := range b {
		for i8 > 0 {
			out = out != ((i8 & 1) == 1) // xor out with lowest bit of i8
			i8 >>= 1
		}
	}
	return
}

func SumOfBits(b Block) (ones uint) {
	ones = 0
	for _, i8 := range b {
		for i8 > 0 {
			ones += uint(i8 & 1)
			i8 >>= 1
		}
	}
	return ones
}

func BlockXOR(b1 Block, b2 Block) (Block) {
	if len(b1) != len(b2) {
		//ERROR
	}
	N := uint(len(b1))
	var out = make([]uint8, N)
	for i := uint(0); i < N; i++ {
		out[i] = b1[i] ^ b2[i]
	}

	return out
}

func BlockAND(b1 Block, b2 Block) (Block) {
	if len(b1) != len(b2) {
		//ERROR
	}
	N := uint(len(b1))
	var out = make([]uint8, N)
	for i := uint(0); i < N; i++ {
		out[i] = b1[i] & b2[i]
	}

	return out
}

func BlockDOT(b1 Block, b2 Block) (bool) {
	return ParityOfBits(BlockAND(b1, b2))
}

func BlockAllOnes(b Block) bool {
	for _, v := range b {
		if v != 255 { // Careful
			return false
		}
	}
	return true
}

func BlockFlipTopBit(b Block) Block {
	b[0] ^= 128 // Careful
	return b
}

func BlockMoreOnes(b Block) bool {
	return (2*SumOfBits(b) / (uint(len(b)) * INTSIZE)) >= 1
}

func ToggleIthBit(b Block, i int) {
	index := i / (1 << INTSIZE)
	bits := uint(i) % INTSIZE
	mask := uint8(1) << bits

	// fmt.Println(index, bits, mask)
	b[index] ^= mask
	return
}
