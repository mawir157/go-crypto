package main

import (
	// "fmt"
)

func main() {

	rm := ReedMuller(2, 5)
	// rm := ReedMuller(3, 7)
	// rm := ReedMuller(4, 9)
	// rm := ReedMuller(5, 11)

	rm.Print()

	textMessage :=
`It was the best of times, it was the worst of times, it was the age of wisdom,
it was the age of foolishness, it was the epoch of belief, it was the epoch of
incredulity, it was the season of Light, it was the season of Darkness, it was
the spring of hope, it was the winter of despair, we had everything before us,
we had nothing before us, we were all going direct to Heaven, we were all going
direct the other way – in short, the period was so far like the present period,
that some of its noisiest authorities insisted on its being received, for good
or for evil, in the superlative degree of comparison only.`

	// message := PadBlock(ParseText(textMessage), len(rm.M) / int(INTSIZE))
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

	// permn := RandomPermutaion(len(rm.M))
	// rmNew := rm.PermuteRows(permn)

	// rmNew.Print()

	// cipherText := rmNew.Encrypt(message, false)
	// PrintHex(message, true)
	// fmt.Println("")
	
	// plaintext := rm.Decrypt(cipherText, true)
	// PrintHex(plaintext, true)
	// fmt.Println("")

	// plaintext = ApplyPerm(plaintext, permn, true)
	// PrintHex(plaintext, true)
	// fmt.Println("")

	// PrintAscii(plaintext, true)

	public, private := generateKeyPair(5)
	cipherText := public.Encrypt(textMessage)
	plaintext := private.Decrypt(cipherText)
	PrintAscii(plaintext, true)

 	return
}
