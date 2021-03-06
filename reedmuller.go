package main

import (
	"fmt"
	"math/rand"
	"time"
)

type RMCode struct {
	r,m      uint
	inBits   uint
	outBits  uint
	M        []Block
	diffs    [][]uint
	errors   uint
}

func ReedMuller(r uint, m uint) RMCode {
	k := uint(0)
	n := uint(1 << m)
	rm := []Block{}
	diffs := [][]uint{}
	for i := uint(0); i <= r; i++ {
		k += Choose(m, i)
	}

	counter := uint(0)
	indices := [][]uint{}
	ordinals := []uint{}

	for i := n; i > 0; i = i / 2 {
		indices = append(indices, []uint{counter})
		rm = append(rm, AlternatingVector(i, n))
		if counter != 0 {
			ordinals = append(ordinals, counter)
		}

		counter++ 
	}

	for i := uint(2); i <= r; i++ {
		additional := GetWedges(rm[1:(m+1)], i)
		newIndices := Pool(i, ordinals)
		
		for _, v := range additional {
			rm = append(rm, v)
		}

		for _, v := range newIndices {
			indices = append(indices, v)
		}

	}

	diffs = InvertIndices(m, indices)
	inBits  := k
	outBits := uint(1 << m)
	
	return RMCode{r:r, m:m, M:rm, diffs:diffs, inBits:inBits, outBits:outBits}
}
func (rm RMCode) Encrypt(msg Block, addErrors bool) (ctxt Block) {
	N := rm.inBits // the number of bit in each plaintext Block
	P := rm.outBits / INTSIZE // the number of bytes in each cipher text block

	row := uint(0)

	var cipherBlock = make([]uint8, P)
	for _, byte := range msg {
		byte = ReverseBits(byte)
		for bit := uint(0); bit < INTSIZE; bit++ {
			t := byte & 1
			if t == 1 {
				cipherBlock = BlockXOR(cipherBlock, rm.M[row])
			} else {
			
			}
			byte >>= 1
			row += 1
		}
		
		if row == N {
			row = 0
			ctxt = append(ctxt, cipherBlock[:]...)
			cipherBlock = make([]uint8, P)
		}
	}

	if addErrors {
		errors := ((1 << (rm.m - rm.r)) - 1) / 2
		bytes := int((1 << rm.m) / INTSIZE)
		fmt.Printf("Adding %d errors for every %d bytes.\n", errors, bytes)

		ctxt = AddErrors(ctxt, errors, bytes)
	}

	return
}

func (rm RMCode) Decrypt(msg []uint8, fixErrors bool) (ptxt Block) {
	P := int(rm.outBits / INTSIZE) // the number of bytes in each cipher text block
	// get the characteristic vectors
	charVectors := [][]Block{}
	for i := 0; i < len(rm.M); i++ {
		charVectors = append(charVectors, getCharVectors(rm, i))
	}

	for i := 0; i < len(msg); i += P {
		eword := make(Block, P)
		copy(eword, msg[i:i+P])
		ewordTemp := make(Block, len(eword))
		copy(ewordTemp, eword)

		coeffs := make([]uint, len(rm.M))

		// compare this block to char vectors for each index
		// iterate backwards through charVectors
		for j := len(charVectors) - 1; j >= 0; j-- {
			chrVecs := charVectors[j]
			votesForOne := uint(0)
			for _, cv := range chrVecs {
				if BlockDOT(cv, eword) {
					votesForOne += 1
				}
			}

			if votesForOne == uint(len(charVectors[j])) - votesForOne {
				fmt.Println("DANGER!")
			} 

			if fixErrors {
				if votesForOne > uint(len(charVectors[j])) - votesForOne {
					ewordTemp = BlockXOR(rm.M[j], ewordTemp)
					coeffs[j] = 1
				} 
			} else {
				if votesForOne == uint(len(charVectors[j])) {
					ewordTemp = BlockXOR(rm.M[j], ewordTemp)
					coeffs[j] = 1
				} 				
			}


			if (j == 0) || (len(rm.diffs[j]) != len(rm.diffs[j-1])) {
				copy(eword, ewordTemp)
			}
		}

		flag := BlockMoreOnes(eword)

		plainTextBlock := Block{}

		for i := 0; i < len(coeffs);  {
			byte := uint8(0)
			for bit := uint(0); bit < INTSIZE; bit++ {
				byte <<= 1	
				if coeffs[i] == 1 {
					byte |= 1
				}
				i++
			}
			plainTextBlock = append(plainTextBlock, byte)
		}

		if flag {
			plainTextBlock = BlockFlipTopBit(plainTextBlock)
		}

		ptxt = append(ptxt, plainTextBlock...)
	}

	return
}

func getCharVectors(rm RMCode, row int) (chars []Block) {
	n := int((1 << rm.m) / INTSIZE)  // probably 2^rm.m
	initial := make(Block, n)
	ones    := make(Block, n)
	for i := 0; i < n; i++ {
		initial[i] = 255 // CAREFUL
		ones[i]    = 255
	}

	chars = []Block{initial}

	for _, index := range rm.diffs[row] {
		fold := rm.M[index] // grab the ith row of the r-m matrix
		notFold := InvertBits(fold) //

		temp := []Block{}
		for _, v := range chars {
			temp = append(temp, BlockAND(v, fold))
			temp = append(temp, BlockAND(v, notFold))
		}
		chars = temp
	}

	return
}

// 'n' errors per 'k' bytes
func AddErrors(ctext Block, n, k int) Block {
  s1 := rand.NewSource(time.Now().UnixNano())
  r1 := rand.New(s1)

  ctextErr := make(Block, len(ctext))
  copy(ctextErr, ctext)

  for blockId := 0; blockId < len(ctext); blockId += k {
  	for errCount := 0; errCount < n; errCount++ {
  		err :=  uint8(1)
  		err <<= r1.Intn(int(INTSIZE))
  		ctextErr[blockId + r1.Intn(k)] ^= err
  	}
  }
	return ctextErr
}

func (rm RMCode) PermuteRows(perm []int) (RMCode) {
	mNew := make([]Block, len(rm.M))

	for i := 0; i < len(perm); i++ {
		mNew[perm[i]] = rm.M[i]
	}

	return RMCode{r:rm.r, m:rm.m, M:mNew, diffs:rm.diffs, inBits:rm.inBits,
	              outBits:rm.outBits}
}

func (rm RMCode) Print() {
	fmt.Printf("In bits = %d | ", rm.inBits)
	fmt.Printf("Out bits = %d\n\n", rm.outBits)

	for _, r := range rm.M {
		PrintBin(r, true)
	}
	fmt.Printf("\n")

	return
}