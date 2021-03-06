package main

import (
	"fmt"
	"math/rand"
)

func GetBitAt(b Block, n int) (bool) {
	// find the byte
	byte := n / int(INTSIZE)
	// find the bit within the byte
	bit := n % int(INTSIZE)

	return ( ((b[byte] >> (int(INTSIZE) - bit - 1)) & 1) == 1 )
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

func RandomPermutaion(n int) []int {
  return rand.Perm(n)
}

func (rm RMCode) permuteRows(perm []int) (RMCode) {
	mNew := make([]Block, len(rm.M))

	for i := 0; i < len(perm); i++ {
		mNew[perm[i]] = rm.M[i]
	}

	return RMCode{r:rm.r, m:rm.m, M:mNew, diffs:rm.diffs, inBits:rm.inBits,
	              outBits:rm.outBits}
}


func main() {

	// rm := ReedMuller(2, 5)
	// rm := ReedMuller(3, 7)
	// rm := ReedMuller(4, 9)
	rm := ReedMuller(5, 11)

	// for i, r := range rm.M {
	// 	// PrintBin(r, false)
	// 	// fmt.Println(i, rm.diffs[i])
	// 	// fmt.Println(i, len(GetCharVectors(rm, id25[i])))
	// }

	fmt.Println("In bits = ", len(rm.M))
	fmt.Println("Out bits = ", INTSIZE*uint(len(rm.M[0])))

	textMessage :=
`It was the best of times, it was the worst of times, it was the age of wisdom,
it was the age of foolishness, it was the epoch of belief, it was the epoch of
incredulity, it was the season of Light, it was the season of Darkness, it was
the spring of hope, it was the winter of despair, we had everything before us,
we had nothing before us, we were all going direct to Heaven, we were all going
direct the other way – in short, the period was so far like the present period,
that some of its noisiest authorities insisted on its being received, for good
or for evil, in the superlative degree of comparison only.`

	message := PadBlock(ParseText(textMessage), len(rm.M) / int(INTSIZE))
	// withErrors := true
	// cipherText := rm.Encrypt(message, withErrors)
	// plaintext := rm.Decrypt(cipherText, withErrors)

	// PrintHex(cipherText, true)
	// PrintHex(plaintext, true)
	// PrintHex(BlockXOR(message, plaintext), true)
	// PrintAscii(plaintext, true)

	// PrintBin(message, true)
	// permn := RandomPermutaion(len(rm.M))
	// message = ApplyPerm(message, permn, true)
	// PrintBin(message, true)
	// message = ApplyPerm(message, permn, false)
	// PrintBin(message, true)
	// PrintAscii(message, true)



	permn := RandomPermutaion(len(rm.M))
	rmNew := rm.permuteRows(permn)
	cipherText := rmNew.Encrypt(message, false)
	PrintHex(message, true)
	fmt.Println("")
	
	plaintext := rm.Decrypt(cipherText, true)
	PrintHex(plaintext, true)
	fmt.Println("")

	plaintext = ApplyPerm(plaintext, permn, true)
	PrintHex(plaintext, true)
	PrintAscii(plaintext, true)

 	return
}
