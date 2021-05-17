package jmtcrypto

import (
	"time"
)

// Mersenne19937 - 
type Mersenne19937 struct {
	w,n,m,r   int

	MT      []uint32
	index     int
	lowerMask uint32
	upperMask uint32
}

// Mersenne19937Init - 
func Mersenne19937Init() *Mersenne19937 {
	w, n, m, r := 32, 624, 397, 31

	index := -1
	MT := make([]uint32, n)

	lowerMask := uint32(0x7fffffff)
	upperMask := uint32(0x80000000)

	return &Mersenne19937{w:w, n:n, m:m, r:r, MT:MT, index:index,
	                      lowerMask:lowerMask, upperMask:upperMask}
}

// Seed - 
func (rng *Mersenne19937) Seed(seed int) {
	if seed <= 0 {
 		seed = int(time.Now().UnixNano())
	}

	f := uint32(1812433253)

	rng.MT[0] = uint32(seed)
	for i := 1; i < rng.n; i++ {
		rng.MT[i] = (f * (rng.MT[i - 1] ^ (rng.MT[i - 1] >> (rng.w - 2))) + uint32(i)) & 0xFFFFFFFF
	}
	rng.index = rng.n
}

// Next - 
func (rng *Mersenne19937) Next() int {
	if rng.index >= rng.n {
		rng.twist()
	}

	y := rng.MT[rng.index]
	y = y ^ ((y >> 11) & 0xFFFFFFFF)
	y = y ^ ((y <<  7) & 0x9D2C5680)
	y = y ^ ((y << 15) & 0xEFC60000)
	y = y ^  (y >> 18)

	rng.index++

	// mersenne19937 returns 32-bit values
	y &= 0xFFFFFFFF

	return int(y)
}


func (rng *Mersenne19937) twist() {
	a := uint32(0x9908B0DF)
	for i := 0; i < rng.n; i++ {
		x := (rng.MT[i] & rng.upperMask) + (rng.MT[(i+1) % rng.n] & rng.lowerMask)
		xA := x >> 1
		if (x & 1) != 0 {
			xA = xA ^ a
		}
		rng.MT[i] = rng.MT[(i + rng.m) % rng.n] ^ xA		
	}

	rng.index = 0
}

// Stream - 
func (rng *Mersenne19937) Stream(n int) (out []int) {
	out = make([]int, n)
	for i := 0; i < n; i++ {
		v := rng.Next()
		out[i] = v 
	}
	return out
}
// UnTwist - 
func UnTwist(y int) int {
	// write out the bits, it is obvious but tedious!
	// UNDO y = y = y ^ (y >> 18)
	y = y ^ (y >> 18)
	// UNDO y = y ^ ((y << 15) & 0xEFC60000)
	y = y ^ ((y << 15) & 0xEFC60000)
	// UNDO y = y ^ ((y << 7) & 0x9D2C5680)
	y = y ^ ((y << 7) & 0x00001680)
	y = y ^ ((y << 7) & 0x000C4000)
	y = y ^ ((y << 7) & 0x0D200000)
	y = y ^ ((y << 7) & 0x90000000)
	// UNDO y = y ^ ((y >> 11) & 0xFFFFFFFF)
	y = y ^ ((y >> 11) & 0xFFC00000)
	y = y ^ ((y >> 11) & 0x003FF800)
	y = y ^ ((y >> 11) & 0x000007FF)

	return y
}

// Splice - 
func (rng *Mersenne19937) Splice(arr []uint32) {
	rng.MT = arr
	rng.index = 0
}
