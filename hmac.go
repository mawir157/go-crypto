package jmtcrypto

import "fmt"

func HMAC(key []byte, msg []byte, hash HashFunction) []byte {
	b := 2*hash.Size() // fix this inner vs outerblock size
	if len(key) > b {
fmt.Println("hash")
		key = hash.Hash(key)
	}

	if len(key) < b {
fmt.Println("pad")
		pad := make([]byte, b - len(key))
		key = append(key, pad...)
	}

fmt.Println(key)
fmt.Println(len(key))

	opad := make([]byte, len(key))
	ipad := make([]byte, len(key))
	for i, v := range key {
		opad[i] = v ^ 0x5c
		ipad[i] = v ^ 0x36
	}

	rhs := hash.Hash(append(ipad, msg...))
	lhs := append(opad, rhs...)

	return hash.Hash(lhs)
}