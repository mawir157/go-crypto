package main

import (
	"fmt"
)

import BS  "./bitset"
import TIO "./textio"
import RM "./reedmuller"



func main() {

	// rm := ReedMuller(2, 5)
	// rm := ReedMuller(3, 7)
	// rm := ReedMuller(4, 9)
	rm := RM.ReedMuller(5, 11)

	// for i, r := range rm.M {
	// 	// TIO.PrintBin(r, false)
	// 	// fmt.Println(i, rm.diffs[i])
	// 	// fmt.Println(i, len(GetCharVectors(rm, id25[i])))
	// }

	fmt.Println("In bits = ", len(rm.M))
	fmt.Println("Out bits = ", BS.INTSIZE*uint(len(rm.M[0])))

	textMessage := "It was the best of times, it was the worst of times! ABCDEF"
	message := TIO.PadBlock(TIO.ParseText(textMessage), len(rm.M) / int(BS.INTSIZE))
	withErrors := true
	cipherText := rm.Encrypt(message, withErrors)
	plaintext := rm.Decrypt(cipherText, withErrors)

	TIO.PrintHex(cipherText, true)
	TIO.PrintHex(plaintext, true)
	TIO.PrintHex(message, true)
	TIO.PrintHex(BS.BlockXOR(message, plaintext), true)
	TIO.PrintAscii(plaintext, true)

 	return
}
