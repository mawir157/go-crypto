package jmtcrypto

import (
	"time"
)

type PRNG interface {
	Seed(seed int)
	Next() int
}

func PRNGStreamEncode(seed int, prng PRNG, msg []byte) (int, []byte) {
	if seed <= 0 {
 		seed = int(time.Now().UnixNano())
	}
	prng.Seed(seed)
	// run the rng for 1000 interations to make sure it is random
	for i := 0; i < 1000; i++ {
		prng.Next()
	}

	out := []byte{}
	var stream [4]byte
	for i, b := range msg {
		if i % 4 == 0 {
			// generate a 4 byte integer
			ri := prng.Next()
			stream = intToBytes(ri)
		}
		out = append(out, b ^ stream[i % 4])
	}

	return seed, out
}

func PRNGStreamDecode(seed int, prng PRNG, msg []byte) ([]byte) {
	_, out := PRNGStreamEncode(seed, prng, msg)

	return out
}


func intToBytes(i int) [4]byte {
	var bs = [4]byte{}

	bs[3] = byte(i)
	bs[2] = byte(i >> 8)
	bs[1] = byte(i >> 16)
	bs[0] = byte(i >> 24)

	return bs
}