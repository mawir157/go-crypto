package jmtcrypto

import (
	"time"
)

import JMTR "github.com/mawir157/jmtcrypto/rand"

func MersenneStreamEncode(seed int, msg []byte) (int, []byte) {
	if seed == -1 {
 		seed = int(time.Now().UnixNano())
	}
	rng := JMTR.Mersenne19937Init(seed)

	out := []byte{}
	var stream [4]byte
	for i, b := range msg {
		if i % 4 == 0 {
			// generate a 4 byte integer
			ri,_ := rng.Extract(false)
			stream = intToBytes(ri)
		}
		out = append(out, b ^ stream[i % 4])
	}

	return seed, out
}

func intToBytes(i int) [4]byte {
	var bs = [4]byte{}

	bs[3] = byte(i)
	bs[2] = byte(i >> 8)
	bs[1] = byte(i >> 16)
	bs[0] = byte(i >> 24)

	return bs
}