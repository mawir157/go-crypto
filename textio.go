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

func ParseForAES(s string) []Word {
	msg := make([]Word, 0)
	counter := 0
	var w Word
	for _, char := range s {
		w[counter] = byte(char)
		counter++
		if counter == 4 {
			counter = 0
			msg = append(msg, w)
		}
	}

	if counter != 0 {
		for i := counter; i < 4; i++ {
			w[i] = 0
		}
		msg = append(msg, w)
	}

	if len(msg) % 4 != 0 {
		pad := 4 - (len(msg) % 4)
		for i := 0; i < pad; i++ {
			msg = append(msg, Word{0,0,0,0})
		}	
	}
	return msg
}

func DearseForAES(ws []Word) (s string) {
	var sb strings.Builder

	for _, w := range ws {
		for _, b := range w {
			sb.WriteString(string(rune(b)))
		}
	}

	return sb.String()
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

func compareSlice(ws1, ws2 []Word) bool {
	if len(ws1) != len(ws2) {
		return false
	}
	for i, v := range ws1 {
		if v != ws2[i] {
			return false
		}
	}
	return true	
}

func aesECBTest(fname string) {
	fmt.Println(fname)

	b, err := ioutil.ReadFile(fname)
	if err != nil { return }

	lines := strings.Split(string(b), "\n")

	mode := true
	for i := 9; i < len(lines); i++ {
		if (lines[i] == "[DECRYPT]\r") {
			mode = false
			i += 2
		}

		if len(lines[i]) == 0 { break }

		parts := strings.Split(lines[i], " = ") // COUNT
		i++

		parts = strings.Split(lines[i], " = ") // KEY
		aes_key := ParseHex(strings.TrimSuffix(parts[1], "\r"))
		i++
		aes := MakeAES(aes_key)

		parts = strings.Split(lines[i], " = ") // PLAIN/CIPHERTEXT
		aes_message := ParseHex(strings.TrimSuffix(parts[1], "\r"))
		i++

		var cipher = make([]Word, 0)

		if mode {
			cipher = ECBEncrypt(aes, aes_message)
		} else {
			cipher = ECBDecrypt(aes, aes_message)
		}

		parts = strings.Split(lines[i], " = ") // CIPHER/PLAINTEXT
		compare := ParseHex(strings.TrimSuffix(parts[1], "\r"))

		if (!compareSlice(cipher, compare)) {
			fmt.Printf("Failed!\n")
			for _, b := range cipher {
				fmt.Printf("%02x", b )
			}
			fmt.Printf("\n")
			for _, b := range compare {
				fmt.Printf("%02x", b )
			}
			fmt.Printf("\n")
		}

		i++
	}
	return
}

func aesCBCTest(fname string) {
	fmt.Println(fname)

	b, err := ioutil.ReadFile(fname)
	if err != nil { return }

	lines := strings.Split(string(b), "\n")

	mode := true
	for i := 9; i < len(lines); i++ {
		if (lines[i] == "[DECRYPT]\r") {
			mode = false
			i += 2
		}

		if len(lines[i]) == 0 { break }

		parts := strings.Split(lines[i], " = ") // COUNT
		i++

		parts = strings.Split(lines[i], " = ") // KEY
		aes_key := ParseHex(strings.TrimSuffix(parts[1], "\r"))
		i++
		aes := MakeAES(aes_key)

		parts = strings.Split(lines[i], " = ") // IV
		var iv [4]Word
		temp := ParseHex(strings.TrimSuffix(parts[1], "\r"))
		copy(iv[:], temp)		
		i++

		parts = strings.Split(lines[i], " = ") // PLAIN/CIPHERTEXT
		aes_message := ParseHex(strings.TrimSuffix(parts[1], "\r"))
		i++

		var cipher = make([]Word, 0)

		if mode {
			cipher = CBCEncrypt(aes, iv, aes_message)
		} else {
			cipher = CBCDecrypt(aes, iv, aes_message)
		}

		parts = strings.Split(lines[i], " = ") // CIPHER/PLAINTEXT
		compare := ParseHex(strings.TrimSuffix(parts[1], "\r"))

		if (!compareSlice(cipher, compare)) {
			fmt.Printf("Failed!\n")
			for _, b := range cipher {
				fmt.Printf("%02x", b )
			}
			fmt.Printf("\n")
			for _, b := range compare {
				fmt.Printf("%02x", b )
			}
			fmt.Printf("\n")
		}

		i++
	}
	return
}
