package main

const INTSIZE int = 8
type Block         = []uint8

func ReverseBits(n uint8) (rev uint8) {
	for i := 0; i < INTSIZE; i++ {
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

func SumOfBits(b Block) (ones int) {
	ones = 0
	for _, i8 := range b {
		for i8 > 0 {
			ones += int(i8 & 1)
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
	return (2*SumOfBits(b) / (len(b) * INTSIZE)) >= 1
}

func ToggleIthBit(b Block, i int) {
	index := i / (1 << INTSIZE)
	bits := i % INTSIZE
	mask := uint8(1) << bits

	b[index] ^= mask
	return
}

func GetBitAt(b Block, n int) (bool) {
	// find the byte
	byte := n / INTSIZE
	// find the bit within the byte
	bit := n % INTSIZE

	return ( ((b[byte] >> (INTSIZE - bit - 1)) & 1) == 1 )
}

func SetBitAt(b Block, n int) (Block) {
	// find the byte
	byte := n / int(INTSIZE)
	// find the bit within the byte
	bit := n % int(INTSIZE)

	b[byte] |= (1 << (int(INTSIZE) - bit - 1))

	return b
}

func ClearBitAt(b Block, n int) (Block) {
	// find the byte
	byte := n / int(INTSIZE)
	// find the bit within the byte
	bit := n % int(INTSIZE)

  mask := ^(uint8(1) << bit)
  b[byte] &= mask

	return b
}

func ApplyPerm(b Block, perm []int, forward bool) (bNew Block) {
	bytesPerPerm := len(perm) / int(INTSIZE)

  for blockId := 0; blockId < len(b); blockId += bytesPerPerm {
		bTemp := make(Block, bytesPerPerm)

		for i := 0; i < len(perm); i++ {
			if forward {
				// send bit i to perm[i]
				if GetBitAt(b[blockId:blockId+bytesPerPerm], i) { // if the bit is one
					bTemp = SetBitAt(bTemp, perm[i])
				}
		  } else {
				// send bit perm[i] to bit i
				if GetBitAt(b[blockId:blockId+bytesPerPerm], perm[i]) { // if the bit is one
					bTemp = SetBitAt(bTemp, i)
				}
			}
		}
		bNew = append(bNew, bTemp...)
  }

	return
}
