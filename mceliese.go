package main

import (
	"fmt"
	// "io/ioutil"
	"os"
	// "strconv"
	// "strings"
)

type PublicKey struct {
	RM	RMCode
}

type PrivateKey struct {
	RM			RMCode
	perm    []int
	C_inv   []Bitset
}

func generateKeyPair(r, m int) (PublicKey, PrivateKey) {
	privateRM := ReedMuller(r, m)

	privateRM.Print(false)

	perm := RandomPermutaion(privateRM.outBits)
	C, C_inv := MatrixPair(privateRM.inBits)

	publicRM := privateRM.PermuteCols(perm)
	publicRM.M = MatMulMat(C, publicRM.M)

	return PublicKey{RM:publicRM},
	       PrivateKey{RM:privateRM, perm:perm, C_inv:C_inv}
}

func (pubKey PublicKey) Encrypt(str string) Bitset {
	message := PadBlock(ParseText(str), pubKey.RM.inBits)

	return pubKey.RM.Encrypt(message, true)
}

func (privKey PrivateKey) Decrypt(cipherText Bitset) Bitset {
	// undo the permutation
	cipherText = ApplyPermToBitset(cipherText, privKey.perm, true)
	// apply standard rm decryption
	cipherText = privKey.RM.Decrypt(cipherText, true)
	// right multiply by C_inv
	postCipher := Bitset{}
	P := privKey.RM.inBits
	for i := 0; i < len(cipherText); i += P {
		eword := make(Bitset, P)
		copy(eword, cipherText[i:i+P])
		eword = MatMulVecR(eword, privKey.C_inv)

		postCipher = append(postCipher, eword...)
	}

	return postCipher
}

func (pubKey PublicKey) Write(filePath string) {
	fmt.Println("Saving public key...")
	f, _ := os.Create(filePath)

	defer f.Close()

	f.WriteString(fmt.Sprintf("%d|%d", pubKey.RM.r, pubKey.RM.m))

	f.WriteString("\n")

	for _, row := range pubKey.RM.M {
		for _, bit := range row {
			if bit {
				f.WriteString("1")
			} else {
				f.WriteString("0")
			}
		}
		f.WriteString("\n")
	}

	f.Sync()
	return
}

func (privKey PrivateKey) Write(filePath string) {
	fmt.Println("Saving private key...")
	f, _ := os.Create(filePath)

	defer f.Close()

	// This is probably unnecessary, we could just saze the coefficients of the
	// Reed Muller Code
	for _, row := range privKey.RM.M {
		for _, bit := range row {
			if bit {
				f.WriteString("1")
			} else {
				f.WriteString("0")
			}
		}
		f.WriteString("\n")
	}
	f.WriteString("\n")
	f.WriteString("\n")

	for _, row := range privKey.C_inv {
		for _, bit := range row {
			if bit {
				f.WriteString("1")
			} else {
				f.WriteString("0")
			}
		}
		f.WriteString("\n")	
	}
	f.WriteString("\n")
	f.WriteString("\n")

	for _, i := range privKey.perm {
		f.WriteString(fmt.Sprintf("%d ", i))
	}
	f.WriteString("\n")

	f.Sync()
	return
}

// func ReadPublic2(fname string) (rm PublicKey) {
// 	b,_ := ioutil.ReadFile(fname)

// 	// type RMCode struct {
// 	// 	r,m      int
// 	// 	inBits   int
// 	// 	outBits  int
// 	// 	M        []Block
// 	// 	diffs    [][]int
// 	// 	errors   int
// 	// }	

// 	M := []Bitset{}

// 	lines := strings.Split(string(b), "\n")
// 	for i, l := range lines {
// 		if len(l) == 0 { continue }

// 		if i == 0 {
// 			parts := strings.Split(l, "|")
// 			n, _ := strconv.Atoi(parts[0])
// 			rm.RM.r = n
// 			n, _ = strconv.Atoi(parts[1])
// 			rm.RM.m = n
// 		} else {
// 			// Empty line occurs at the end of the file when we use Split.
// 			hexes := strings.Split(l, " ")
// 			row := make(Bitset, 0)
// 			for _, h := range hexes {
// 				if h == "" {
// 					continue
// 				}

// 				i,_ := strconv.ParseInt(h, 16, 16)
// 				byte := uint8(i)
// 				row = append(row, byte)
// 			}
// 			M = append(M, row)
// 		}
// 	}
// 	rm.RM.M = M
// 	rm.RM.inBits = len(M)
// 	rm.RM.outBits = len(M[0])

// 	return rm
// }
