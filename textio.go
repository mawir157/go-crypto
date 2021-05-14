package jmtcrypto

import (
	"encoding/hex"
	"encoding/base64"
	"errors"
	"strings"
)

////////////////////////////////////////////////////////////////////////////////
//
// Convert to and from bytes
//

// ParseFromASCII - 
func ParseFromASCII(str string, pad bool) ([]byte, error) {
	msg := make([]byte, 0)
	for _, char := range str {
		msg = append(msg, byte(char))
	}
	if pad {
		padValue := byte(16 - (len(msg) % 16))
		for i := byte(0); i < padValue; i++ {
			msg = append(msg, padValue)
		}
	}

	return msg, nil
}

// ParseToASCII -
func ParseToASCII(bs []byte, pad bool) (string, error) {
	var sb strings.Builder

	if pad {
		final := bs[len(bs) - 1]
		bs = bs[:len(bs)-int(final)]
	}

	for _, b := range bs {
		sb.WriteString(string(rune(b)))
	}

	return sb.String(), nil
}

// ParseFromHex -
func ParseFromHex(s string, pad bool) ([]byte, error) {
	data, err := hex.DecodeString(s)
	if err != nil {
		// panic(err)
		return []byte{}, errors.New("invalid hex string")
	}

	if pad {
		padValue := byte(16 - (len(data) % 16)) % 16
		for i := byte(0); i < padValue; i++ {
			data = append(data, padValue)
		}		
	}	

	return data, nil
}

// ParseToHex - 
func ParseToHex(bts []byte) (string, error) {
	return hex.EncodeToString(bts), nil
}

// ParseFromBase64 -
func ParseFromBase64(s string, pad bool) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		// panic(err)
		return []byte{}, errors.New("invalid base64 string")
	}

	if pad {
		padValue := byte(16 -(len(data) % 16)) % 16
		for i := byte(0); i < padValue; i++ {
			data = append(data, padValue)
		}		
	}	

	return data, nil
}

// ParseToBase64 - 
func ParseToBase64(bts []byte) (string, error) {
	return base64.StdEncoding.EncodeToString(bts), nil
}

func bytesToWords(data []byte, pad bool) (parsed []Word) {
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

func wordsToBytes(ws []Word) (data []byte) {
	for _ , w := range ws {
		data = append(data, w[:]...)
	}

	return
}

func addBytePad(bs []byte) []byte {
	padValue := byte(16 -(len(bs) % 16))

	for i := byte(0); i < padValue; i++ {
		bs = append(bs, padValue)
	}

	return bs
}

func removeBytePad(bs []byte) ([]byte, error) {
	err := validatePad(bs)

	if err != nil {
		return bs, err
	}
	final := int(bs[len(bs) - 1])

	return bs[:len(bs) - final], nil
}

// The Error messages are intentially vague to prevent leaking information!
func validatePad(bs []byte) (error) {
	final := bs[len(bs) - 1]
	if len(bs) % 16 != 0 {
		return errors.New("invalid pad")
	}

	if int(final) > len(bs) {
		return errors.New("invalid pad")
	}

	if final == 0x00 {
		return errors.New("invalid pad")
	}

	if final > 0x10 {
		return errors.New("invalid pad")
	}

	for b := 0; b < int(final); b++ {
		if bs[len(bs) - 1 - b] != final {
			return errors.New("invalid pad")
		}
	}
	return nil
}