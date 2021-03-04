package TextIO

import (
	"fmt"
)

import BS "../bitset"

func ParseText(s string) BS.Block {
	msg := make(BS.Block, len(s))
	for i, char := range s {
		msg[i] = uint8(char)
	}
	return msg
}

func DeparseMessage(b BS.Block) string {
	message := ""
	for _, char := range b {
		message = message + string(rune(char))
	}
	return message 
}

func PrintHex(b BS.Block) {
	for _, char := range b {
		fmt.Printf("%02X ", char)
	}
	fmt.Println("")
}

func PadBlock(b BS.Block, n int) BS.Block {
	need := (len(b) % n)

	if need == 0 {
		return b
	}

	pad := make(BS.Block, n - need)
	b = append(b, pad...)
	
	return b
}

func PrintBin(b BS.Block) {
	for _, char := range b {
		fmt.Printf("%08b ", char)
	}
	fmt.Println("")
}