package main

import (
	"fmt"
)

func ParseText(s string) Block {
	msg := make(Block, len(s))
	for i, char := range s {
		msg[i] = uint8(char)
	}
	return msg
}

func DeparseMessage(b Block) string {
	message := ""
	for _, char := range b {
		message = message + string(rune(char))
	}
	return message 
}

func PrintHex(b Block,  newLine bool) {
	for _, char := range b {
		fmt.Printf("%02X ", char)
	}

	if newLine {
		fmt.Println("")
	}
}

func PadBlock(b Block, n int) Block {
	need := (len(b) % n)

	if need == 0 {
		return b
	}

	pad := make(Block, n - need)
	b = append(b, pad...)
	
	return b
}

func PrintBin(b Block, newLine bool) {
	for _, char := range b {
		fmt.Printf("%08b ", char)
	}
	if newLine {
		fmt.Println("")
	}
}

func PrintAscii(b Block, newLine bool) {
	fmt.Print(DeparseMessage(b))
	if newLine {
		fmt.Println("")
	}
}
