package main

import (
	"fmt"
	"math"
	"math/rand"
	"time"
)

import BS "./bitset"
import CB "./combinatorics"

func AlternatingVector(run, n uint) (v []uint8) {
	ui8 := uint8(0)
	runcount := uint(0)
	runflag := true
	for i := uint(0); i < n; i++ {
		if runflag {
			ui8 |= 1
		}

		if (i % BS.INTSIZE) == (BS.INTSIZE - 1) {
			v = append(v, ui8)
			ui8 = 0
		}
		ui8 <<= 1

		runcount += 1
		if runcount == run {
			runflag = !runflag
			runcount = 0
		}
	}
	return 
}

func GetCharVectors(rm []BS.Block, indices []uint) (chars []BS.Block) {
	n := len(rm[0]) 
	initial := make(BS.Block, n)
	ones    := make(BS.Block, n)
	for i := 0; i < n; i++ {
		initial[i] = 255 // CAREFUL
		ones[i]    = 255
	}

	chars = []BS.Block{initial}

	for _, index := range indices {
		fold := rm[index] // grab the ith row of the r-m matrix
		notFold := BS.BlockXOR(ones, fold) //

		temp := []BS.Block{}
		for _, v := range chars {
			temp = append(temp, BS.BlockAND(v, fold))
			temp = append(temp, BS.BlockAND(v, notFold))
		}
		chars = temp
	}

	return
}

func ReedMuller(r uint, m uint) (rm []BS.Block, diffs [][]uint) {
	k := uint(0)
	n := uint(math.Pow(2, float64(m)))
	for i := uint(0); i <= r; i++ {
		k += CB.Choose(m, i)
	}

	counter := uint(0)
	indices := [][]uint{}

	for i := n; i > 0; i = i / 2 {
		indices = append(indices, []uint{counter})
		rm = append(rm, AlternatingVector(i, n))

		counter++ 
	}

	for i := uint(2); i <= r; i++ {
		additional := CB.GetWedges(rm[1:(m+1)], i)
		newIndices := CB.GetCombs(indices[1:(m+1)], i)
		
		for _, v := range additional {
			rm = append(rm, v)
		}

		for _, v := range newIndices {
			indices = append(indices, v)
		}

	}

	diffs = CB.InvertIndices(m, indices)
	
	return
}

func ReedMullerEncrypt(rm []BS.Block, msg []uint8) (ctxt BS.Block) {
	N := uint(len(rm)) // the number of bit in each plaintext Block
	P := len(rm[0])

	row := uint(0)

	var cipherBlock = make([]uint8, P)
	for _, byte := range msg {
		byte = BS.ReverseBits(byte)
		for bit := uint(0); bit < BS.INTSIZE; bit++ {
			t := byte & 1
			if t == 1 {
				cipherBlock = BS.BlockXOR(cipherBlock, rm[row])
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

	return
}

func ReedMullerDecrypt(rm []BS.Block, diffs [][]uint, msg []uint8) (ptxt BS.Block) {
	P := len(rm[0]) // the number of bytes in each ciphertext block

	// get the characteristic
	charVectors := [][]BS.Block{}
	for i := 0; i < len(rm); i++ {
		charVectors = append(charVectors, GetCharVectors(rm, diffs[i]))
	}

	for i := 0; i < len(msg); i += P {
		group := make(BS.Block, P)
		copy(group, msg[i:i+P])
		// group := msg[i:i+P]
		groupTemp := make(BS.Block, len(group))
		copy(groupTemp, group)

		coeffs := make([]uint, len(rm))
		
		// compare this block to char vectors for each index
		// iterate backwards through charVectors
		for j := len(charVectors) - 1; j >= 1; j-- {
			chrVecs := charVectors[j]
			total := uint(0)
			for _, cv := range chrVecs {
				if BS.BlockDOT(cv, group) {
					total += 1
				}
				// fmt.Println(groupTemp)
			}
			coeffs[j] = total


			if coeffs[j] > uint(len(charVectors[j]) / 2) {
				groupTemp = BS.BlockXOR(rm[j], groupTemp)
			} 

			if len(diffs[j]) != len(diffs[j-1]) {
				fmt.Print("*")
				// group = groupTemp
				copy(group, groupTemp)
			}
		}
		fmt.Println("group----->",group)
		fmt.Println("coeffs----->",coeffs)

		flag := BS.BlockMoreOnes(group)

		plainTextBlock := BS.Block{}

		for i := 0; i < len(coeffs);  {
			byte := uint8(0)
			for bit := uint(0); bit < BS.INTSIZE; bit++ {
				byte <<= 1	
				if coeffs[i] > uint(len(charVectors[i]) / 2) {
					byte |= 1
				}
				i++
			}
			plainTextBlock = append(plainTextBlock, byte)
		}

		// fmt.Println(plainTextBlock, "|", group, "~", flag)
		if flag {
			plainTextBlock = BS.BlockFlipTopBit(plainTextBlock)
			// plainTextBlock = BS.BlockXOR(plainTextBlock, group)
		}

		ptxt = append(ptxt, plainTextBlock...)
	}

	return
}

// 'n' errors per 'k' bytes
func AddErrors(ctext BS.Block, n, k int) BS.Block {
  s1 := rand.NewSource(time.Now().UnixNano())
  r1 := rand.New(s1)

  ctextErr := make(BS.Block, len(ctext))
  copy(ctextErr, ctext)

  for blockId := 0; blockId < len(ctext); blockId += k {
  	for errCount := 0; errCount < n; errCount++ {
  		err :=  uint8(1)
  		err <<= r1.Intn(int(BS.INTSIZE))
  		ctextErr[blockId + r1.Intn(k)] ^= err
  	}
  }
	return ctextErr
}

func main() {
	// rm25, id25 := ReedMuller(2, 5)
	// rm25, id25 := ReedMuller(3, 7)
	rm25, id25 := ReedMuller(4, 9)

	fmt.Println("In bits = ", len(rm25))
	fmt.Println("Out bits = ", BS.INTSIZE*uint(len(rm25[0])))

	for i, _ := range rm25 {
		// fmt.Println(i, r, id25[i], len(GetCharVectors(rm25, id25[i])))
		fmt.Println(i, len(GetCharVectors(rm25, id25[i])))
	}

	// fmt.Println("message: ", msg)

	ctxt := ReedMullerEncrypt(rm25, msg[:128])
	fmt.Println("Ciphertext: ", ctxt)
	
	// add errors
	ctxtErr := AddErrors(ctxt, 0, 16)
	fmt.Println("Ciphertext w/ errors: ", ctxtErr)

	fmt.Println(BS.BlockXOR(ctxt, ctxtErr))

	plaintext := ReedMullerDecrypt(rm25, id25, ctxtErr)
	fmt.Println("Plaintext: ", plaintext)

	fmt.Println(len(msg), len(ctxt), len(plaintext))

 	fmt.Println("Errors:", BS.BlockXOR(msg[:128], plaintext))

 	return
}


var msg BS.Block = BS.Block{238,74,16,184,30,103,35,234,90,217,142,157,220,248,103,111,
								187,118,232,42,166,212,193,59,224,17,1,3,104,164,137,89,229,
								91,134,149,138,244,59,10,96,54,22,174,191,243,44,152,192,156,
								40,66,184,114,85,234,2,127,27,177,135,134,47,128,92,138,20,
								200,49,100,26,236,168,93,161,185,51,124,94,91,45,171,82,28,53,
								147,24,178,159,17,221,142,255,149,66,14,13,109,52,42,91,147,
								143,68,30,48,232,9,26,74,148,236,68,5,51,41,159,24,235,30,233,
								169,102,148,71,122,166,139,178,125,82,173,23,0,162,131,217,1,
								115,181,15,178,103,69,83,224,242,136,173,137,60,186,5,211,49,
								11,200,163,22,243,52,100,159,99,187,178,226,163,187,172,54,53,
								65,176,158,44,154,197,155,54,243,69,48,146,110,251,143,225,90,
								218,229,183,12,94,133,232,86,59,148,11,142,198,226,18,52,92,
								185,36,8,168,233,15,206,14,101,207,139,24,218,12,145,41,38,25,
								14,206,182,71,188,87,33,219,132,250,229,187,202,67,189,134,
								114,134,131,133,187,31,181,240,114,183,117,26,136,182,126,217,
								133,165,15,33,128,96,106,26,200,106,32,108,220,12,96,25,182,
								151,93,135,191,30,221,46,138,198,233,100,255,236,141,209,204,
								23,215,189,83,130,178,225,10,144,97,48,164,207,225,29,16,142,
								191,92,198,45,223,142,39,146,233,71,225,39,15,202,158,17,54,
								159,201,94,13,228,100,242,34,166,103,125,42,231,253,73,42,192,
								139,137,246,125,79,209,157,199,74,177,150,35,168,109,142,182,
								172,13,227,140,155,111,199,52,205,11,28,163,244,114,171,217,
								15,173,219,74,103,91,37,153,202,126,209,94,204,57,18,186,231,
								162,48,10,146,189,235,100,143,216,153,198,26,10,110,245,208,
								190,180,75,182,173,139,111,104,133,87,128,90,149,139,175,150,
								165,235,141,150,56,198,105,197,43,220,203,124,230,209,136,146,
								49,209,202,19,120,64,71,190,245,187,94,117,143,217,244,226,
								237,220,59,203,168,5,160,224,22,242,91,218,193,255,168,16,122,
								166,175,46,164,183,229,91,64,185,244,129,78,30,25,242,83,11,
								65,186,152,146,53,228,78,2,37,252,59,162,139,180,248,239,170,
								66,19,20,245,5,185,198,139,34,30,165,218,103,80,33,42,107,203,
								93,49,175,158,180,0,163,226,132,237,214,155,148,134,145,44,71,
								102,202,73,200,61,157,78,161,99,24,202,252,154,238,201,195,
								217,111,146,250,191,166,149,185,84,157,202,42,238,79,164,42,
								92,176,113,254,83,106,219,156,89,226,39,233,211,199,82,226,
								214,37,98,27,87,233,48,182,2,100,255,240,32,118,4,43,27,50,
								240,22,232,242,215,76,159,126,122,254,179,77,213,155,80,132,
								201,61,80,251,74,217,65,195,225,94,220,45,253,8,49,158,43,98,
								239,97,188,43,1,106,241,177,231,137,191,22,180,118,223,203,
								118,139,66,221,77,59,27,201,141,1,252,240,185,187,147,8,17,
								113,138,235,189,92,115,174,92,194,161,48,253,42,197,88,136,
								240,96,76,167,82,114,33,46,33,178,182,201,171,225,98,177,62,
								205,108,50,255,217,100,177,200,31,242,63,175,155,11,61,15,168,
								167,125,220,63,203,24,42,62,37,35,6,50,102,72,111,9,252,121,
								76,203,115,174,134,210,32,39,232,77,138,140,175,171,23,118,
								134,142,195,207,227,142,161,11,144,168,121,233,20,180,46,250,
								223,13,200,222,48,128,191,14,98,33,71,171,37,4,252,98,250,180,
								164,215,217,237,226,240,230,255,163,83,202,203,80,158,126,118,
								186,165,245,18,71,7,56,45,71,164,121,236,152,146,156,2,241,68,
								23,79,222,228,113,25,236,29,98,179,14,248,195,253,167,237,10,
								75,50,2,122,136,253,119,219,62,131,85,119,190,248,6,58,213,35,
								6,121,18,162,202,221,223,238,6,188,152,221,93,124,94,16,8,116,
								194,247,20,121,169,107,254,78,93,167,18,157,99,31,93,233,189,
								15,126,120,159,168,80,69,86,178,217,27,140,80,145,221,156,152,
								202,133,197,69,181,8,137,233,40,151,37,221,242,20,110,92,53,
								118,123,169,157,69,33,108,123,210,164,32,49,136,235,199,244,
								254,168,207,219,112,185,131,149,47,207,15,110,22,35,249,54,
								204,72,39,16,59,135,196,70,137,165,104,14,67,80,185,200,160,
								95,194,203,61,237,32,0,239,198,230,252,123,81,168,229,55,86,
								184,131,141,38,158,255,206,232,181,23,56,17,28,218,203,50,167,
								215,6,189,26,222,88,15,135,127,107,250,61,184}