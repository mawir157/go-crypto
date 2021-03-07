package main

import (
	"fmt"
	"os"
)

type PublicKey struct {
	RM	RMCode
}

type PrivateKey struct {
	RM			RMCode
	perm    []int
	C_inv   []Block
}

func generateKeyPair(r int) (PublicKey, PrivateKey) {
	privateRM := ReedMuller(r, 2*r + 1)

	privateRM.Print(false)

	perm := RandomPermutaion(privateRM.outBits)
	C, C_inv := MatrixPair(privateRM.inBits)

	publicRM := privateRM.PermuteCols(perm)
	publicRM.M = MatMulMat(C, publicRM.M)

	return PublicKey{RM:publicRM},
	       PrivateKey{RM:privateRM, perm:perm, C_inv:C_inv}
}

func (pubKey PublicKey) Encrypt(str string) Block {
	message := PadBlock(ParseText(str), pubKey.RM.inBits / INTSIZE)

	return pubKey.RM.Encrypt(message, true)
}

func (privKey PrivateKey) Decrypt(cipherText Block) Block {
	// undo the permutation
	cipherText = ApplyPerm(cipherText, privKey.perm, true)
	// apply standard rm decryption
	cipherText = privKey.RM.Decrypt(cipherText, true)

	// right multiply by C_inv
	postCipher := Block{}
	P := privKey.RM.inBits / INTSIZE
	for i := 0; i < len(cipherText); i += P {
		eword := make(Block, P)
		copy(eword, cipherText[i:i+P])
		eword = MatMulVecR(eword, privKey.C_inv)

		postCipher = append(postCipher, eword...)
	}

	return postCipher
}

func (pubKey PublicKey) Write(filePath string) {
	f, _ := os.Create(filePath)

	defer f.Close()

	for _, r := range pubKey.RM.M {
		// f.Write(r)
		for _, char := range r {
			f.WriteString(fmt.Sprintf("%02X ", char))
		}
		f.WriteString("\n")
	}

	f.Sync()
	return
}

func (privKey PrivateKey) Write(filePath string) {
	f, _ := os.Create(filePath)

	defer f.Close()

	for _, r := range privKey.RM.M {
		for _, char := range r {
			f.WriteString(fmt.Sprintf("%02X ", char))
		}
		f.WriteString("\n")
	}
	f.WriteString("\n")
	f.WriteString("\n")

	for _, r:= range privKey.C_inv {
		for _, char := range r {
			f.WriteString(fmt.Sprintf("%02X ", char))
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
