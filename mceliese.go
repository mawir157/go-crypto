package main

type PublicKey struct {
	RM	RMCode
}

type PrivateKey struct {
	RM			RMCode
	perm    []int
}

func generateKeyPair(r uint) (PublicKey, PrivateKey) {
	privateRM := ReedMuller(r, 2*r + 1)

	perm := RandomPermutaion(int(privateRM.inBits))
	publicRM := privateRM.PermuteRows(perm)

	return PublicKey{RM:publicRM},
	       PrivateKey{RM:privateRM, perm:perm}
}

func (pubKey PublicKey) Encrypt(str string) Block {
	message := PadBlock(ParseText(str), int(pubKey.RM.inBits) / int(INTSIZE))

	return pubKey.RM.Encrypt(message, true)
}

func (privKey PrivateKey) Decrypt(cipherText Block) Block {
	plaintext := privKey.RM.Decrypt(cipherText, true)

	return ApplyPerm(plaintext, privKey.perm, true)
}