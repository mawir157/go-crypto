package main

import (
	"fmt"
	"io/ioutil"
	"encoding/hex"
  "strings"
)

func CharToBitset(c rune) (bs Bitset) {
	bs = make(Bitset, 8)

	for b := 0; b < 8; b++ {
		bs[b] = ((c >> (7 - b)) & 1) == 1
	}

	return
}

func ParseText(s string) Bitset {
	msg := make(Bitset, 0)
	for _, char := range s {
		binChar := CharToBitset(char)
		msg = append(msg, binChar...)
	}

	return msg
}

func DeparseMessage(bs Bitset) string {
	var sb strings.Builder
	byte := uint8(0)
	for i, b := range bs {
		byte <<= 1
		if b {
			byte += 1
		}

		if i % 8 == 7 {
			sb.WriteString(string(rune(byte)))
			byte = 0
		}
	}
	return sb.String()
}

func PrintHex(b Bitset, newLine bool) {
	plain := DeparseMessage(b)
	for _, char := range plain {
		fmt.Printf("%02x ", char)
	}

	if newLine {
		fmt.Println("")
	}
}

func PadBlock(b Bitset, n int) Bitset {
	need := (len(b) % n)

	if need == 0 {
		return b
	}

	for i := 0; i < n - need; i++ {
		b = append(b, true)
	}

	return b
}

func PrintBin(bs Bitset, newLine bool) {
	for i, b := range bs {
		if b {
			fmt.Print("1")
		} else {
			fmt.Print("0")
		}
		if i % 8 == 7 {
			fmt.Print(" ")
		}
	}
	if newLine {
		fmt.Println("")
	}
}

func PrintAscii(b Bitset, newLine bool) {
	fmt.Print(DeparseMessage(b))
	if newLine {
		fmt.Println("")
	}
}

func ParseHex(s string) ([]Word) {
	parsed := make([]Word, 0)

	data, err := hex.DecodeString(s)
	if err != nil { panic(err) }

	for i := 0; i < len(data); i += 4 {
		parsed = append( parsed, Word{data[i], data[i+1], data[i+2], data[i+3]} )
	}

	return parsed
}


func aesTest(fname string) {
	fmt.Println(fname)

	b, err := ioutil.ReadFile(fname)
	if err != nil { return }

	lines := strings.Split(string(b), "\n")

	mode := true
	for i := 9; i < len(lines); i++ {
		if (lines[i] == "[DECRYPT]\r") { 
			fmt.Println("Changing mode")
			mode = false
			i += 2
		}

		if len(lines[i]) == 0 { break }

		parts := strings.Split(lines[i], " = ")
		fmt.Println(lines[i])
		i++

		parts = strings.Split(lines[i], " = ")
		aes_key := ParseHex(strings.TrimSuffix(parts[1], "\r"))
		fmt.Println(len(aes_key))
		i++
		aes2 := MakeAES(aes_key)

		parts = strings.Split(lines[i], " = ")
		aes_message := ParseHex(strings.TrimSuffix(parts[1], "\r"))
		i++

		if mode {
			cipher := aes2.Encrypt(aes_message)
			fmt.Printf("CIPHERTEXT = ")
			for _, b := range cipher {
				fmt.Printf("%02x", b )
			}
		} else {
			cipher := aes2.Decrypt(aes_message)
			fmt.Printf("FLAINTEXT = ")
			for _, b := range cipher {
				fmt.Printf("%02x", b )
			}
		}
		fmt.Printf("\n")
		fmt.Println(lines[i])
		i++

		fmt.Println("=============================================================")
	}

	return 
}