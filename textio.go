package jmtcrypto

import (
	"fmt"
	"io/ioutil"
	"encoding/hex"
	"encoding/base64"
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

////////////////////////////////////////////////////////////////////////////////
//
// Convert to and from Words
//
func ParseFromAscii(s string) []Word {
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

func ParseToAscii(ws []Word) (s string) {
	var sb strings.Builder

	for _, w := range ws {
		for _, b := range w {
			sb.WriteString(string(rune(b)))
		}
	}

	return sb.String()
}

func ParseFromHex(s string) ([]Word) {
	parsed := make([]Word, 0)

	data, err := hex.DecodeString(s)
	if err != nil { panic(err) }

	for i := 0; i < len(data); i += 4 {
		parsed = append( parsed, Word{data[i], data[i+1], data[i+2], data[i+3]} )
	}

	return parsed
}

func ParseToHex(wds []Word) (s string) {
	bts := make([]byte, 0)
	for _, wd := range wds {
		bts = append(bts, wd[0], wd[1], wd[2], wd[3])
	}

	return hex.EncodeToString(bts)
}

func ParseFromBase64(s string) ([]Word) {
	parsed := make([]Word, 0)

	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil { panic(err) }

	for i := 0; i < len(data); i += 4 {
		parsed = append( parsed, Word{data[i], data[i+1], data[i+2], data[i+3]} )
	}

	return parsed
}

func ParseToBase64(wds []Word) (s string) {
	bts := make([]byte, 0)
	for _, wd := range wds {
		bts = append(bts, wd[0], wd[1], wd[2], wd[3])
	}

	return base64.StdEncoding.EncodeToString(bts)
}

////////////////////////////////////////////////////////////////////////////////
//
// Convert to and from bytes
//
func ParseFromAsciiB(bs string) (msg []byte) {
	msg = make([]byte, 0)
	for _, char := range bs {
		msg = append(msg, byte(char))
	}

	return
}

func ParseToAsciiB(bs []byte) (s string) {
	var sb strings.Builder

	for _, b := range bs {
		sb.WriteString(string(rune(b)))
	}

	return sb.String()
}

func ParseFromHexB(s string) ([]byte) {
	data, err := hex.DecodeString(s)
	if err != nil { panic(err) }

	return data
}

func ParseToHexB(bts []byte) (s string) {
	return hex.EncodeToString(bts)
}

func ParseFromBase64B(s string) ([]byte) {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil { panic(err) }

	return data
}

func ParseToBase64B(bts []byte) (s string) {
	return base64.StdEncoding.EncodeToString(bts)
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
		aes_key := ParseFromHex(strings.TrimSuffix(parts[1], "\r"))
		i++
		aes := MakeAES(aes_key)

		parts = strings.Split(lines[i], " = ") // PLAIN/CIPHERTEXT
		aes_message := ParseFromHex(strings.TrimSuffix(parts[1], "\r"))
		i++

		var cipher = make([]Word, 0)

		if mode {
			cipher = ECBEncrypt(aes, aes_message)
		} else {
			cipher = ECBDecrypt(aes, aes_message)
		}

		parts = strings.Split(lines[i], " = ") // CIPHER/PLAINTEXT
		compare := ParseFromHex(strings.TrimSuffix(parts[1], "\r"))

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
		aes_key := ParseFromHex(strings.TrimSuffix(parts[1], "\r"))
		i++
		aes := MakeAES(aes_key)

		parts = strings.Split(lines[i], " = ") // IV
		var iv [4]Word
		temp := ParseFromHex(strings.TrimSuffix(parts[1], "\r"))
		copy(iv[:], temp)		
		i++

		parts = strings.Split(lines[i], " = ") // PLAIN/CIPHERTEXT
		aes_message := ParseFromHex(strings.TrimSuffix(parts[1], "\r"))
		i++

		var cipher = make([]Word, 0)

		if mode {
			cipher = CBCEncrypt(aes, iv, aes_message)
		} else {
			cipher = CBCDecrypt(aes, iv, aes_message)
		}

		parts = strings.Split(lines[i], " = ") // CIPHER/PLAINTEXT
		compare := ParseFromHex(strings.TrimSuffix(parts[1], "\r"))

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
