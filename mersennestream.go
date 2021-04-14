package jmtcrypto

import (
	"jmtcrypto/rand"
	"time"
)

func MersenneStreamEncode(seed int, msg []byte) ([]byte) {
	if seed == -1 {
  	seed = int(time.Now().UnixNano())
	}
	// rng := JMTR.Mersenne19937Init(time.Now().UnixNano())

	return []byte{}
}