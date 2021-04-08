package jmtcrypto

import (
	"fmt"
	"encoding/hex"
	"encoding/base64"
	"errors"
	// "strconv"
	"strings"
)

////////////////////////////////////////////////////////////////////////////////
//
// Convert to and from Bitsets
//
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
// Convert to and from bytes
//
func ParseFromAscii(str string, pad bool) (msg []byte) {
	msg = make([]byte, 0)
	for _, char := range str {
		msg = append(msg, byte(char))
	}
	if pad {
		padValue := byte(16 - (len(msg) % 16))
		for i := byte(0); i < padValue; i++ {
			msg = append(msg, padValue)
		}
	}

	return
}

func ParseToAscii(bs []byte, pad bool) (s string) {
	var sb strings.Builder

	if pad {
		final := bs[len(bs) - 1]
		bs = bs[:len(bs)-int(final)]
	}

	for _, b := range bs {
		sb.WriteString(string(rune(b)))
	}

	return sb.String()
}

func ParseFromHex(s string, pad bool) ([]byte) {
	data, err := hex.DecodeString(s)
	if err != nil { panic(err) }

	if pad {
		padValue := byte(16 - (len(data) % 16)) % 16
		for i := byte(0); i < padValue; i++ {
			data = append(data, padValue)
		}		
	}	

	return data
}

func ParseToHex(bts []byte) (s string) {
	return hex.EncodeToString(bts)
}

func ParseFromBase64(s string, pad bool) ([]byte) {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil { panic(err) }

	if pad {
		padValue := byte(16 -(len(data) % 16)) % 16
		for i := byte(0); i < padValue; i++ {
			data = append(data, padValue)
		}		
	}	

	return data
}

func ParseToBase64(bts []byte) (s string) {
	return base64.StdEncoding.EncodeToString(bts)
}

func BytesToWords(data []byte, pad bool) (parsed []Word) {
	if pad {
		padValue := byte(16 -(len(data) % 16))

		for i := byte(0); i < padValue; i++ {
			data = append(data, padValue)
		}			
	}
	
	for i := 0; i < len(data); i += 4 {
		parsed = append( parsed, Word{data[i], data[i+1], data[i+2], data[i+3]} )
	}

	return parsed
}

func WordsToBytes(ws []Word) (data []byte) {
	for _ , w := range ws {
		data = append(data, w[:]...)
	}

	return

}

func ValidatePad(bs []byte) (error) {
	final := bs[len(bs) - 1]

	if len(bs) % 16 != 0 {
		return errors.New("Invalid Pad 0")
	}

	if int(final) >= len(bs) {
		return errors.New("Invalid Pad 1")
	}

	if int(final) == 0 {
		return errors.New("Invalid Pad 1")
	}

	for b := 0; b < int(final); b++ {
		if bs[len(bs) - 1 - b] != final {
			return errors.New("Invalid Pad 2")
		}
	}
	return nil
}