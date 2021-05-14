package jmtcrypto

import (
	"time"
)

// PermConGen - 
type PermConGen struct {
	state      uint64
	multiplier uint64
	increment  uint64
}

// PCGInit -
func PCGInit() *PermConGen {
	return &PermConGen{multiplier: 6364136223846793005,
	                   increment:  1442695040888963407}
}

// Seed - 
func (rng *PermConGen) Seed(seed int) {
	if seed == 0 {
		seed = int(time.Now().UnixNano())
	}

	rng.state = uint64(seed) + rng.increment
}

// Next - 
func (rng *PermConGen) Next() int {
		x := rng.state
		count := uint(x >> 59)

		rng.state = x * rng.multiplier + rng.increment
		x = x ^ (x >> 18)

		return rotr32(uint32(x >> 27), count)
}

func rotr32(x uint32, r uint) int {
	return int( (x >> r) | (x << (-r & 31)) )
}
