package main

import (
	"fmt"
)

// import BS  "./bitset"
// import TIO "./textio"

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

	textMessage := "It was the best of times, it was the worst of times! ABCDEF"
	message := PadBlock(ParseText(textMessage), len(rm.M) / int(INTSIZE))
	withErrors := true
	cipherText := rm.Encrypt(message, withErrors)
	plaintext := rm.Decrypt(cipherText, withErrors)

	PrintHex(cipherText, true)
	PrintHex(plaintext, true)
	PrintHex(message, true)
	PrintHex(BlockXOR(message, plaintext), true)
	PrintAscii(plaintext, true)

 	return
}
