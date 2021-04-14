package rand

import (
	"errors"
)

type Mersenne19937 struct {
	w,n,m,r   int

	MT      []int
	index     int
	lowerMask int
	upperMask int
}

func Mersenne19937Init(seed int) Mersenne19937 {
	w, n, m, r := 32, 624, 397, 31

	f := 1812433253
	index := 0
	
	MT := []int{seed}
	for i := 1; i < n; i++ {
		temp := f * (MT[i - 1] ^ (MT[i - 1] >> (w - 2))) + i
		MT = append(MT, temp & 0xFFFFFFFF)
	}

	lowerMask := (1 << r) - 1
	upperMask := 0 

	return Mersenne19937{w:w, n:n, m:m, r:r, MT:MT, index:index,
	                     lowerMask:lowerMask, upperMask:upperMask}
}

func (rng *Mersenne19937) Extract(b32 bool) (int, error) {
	if rng.index >= rng.n {
		if rng.index > rng.n {
			return 0, errors.New("Invalid seed")
		}
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
	if b32 {
		y = int(int32(y))
	}

	return y, nil
}


func (rng *Mersenne19937) twist() error {
	a := 0x9908B0DF
	for i := 0; i < rng.n; i++ {
		x := (rng.MT[i] & rng.upperMask) + (rng.MT[(i+1) % rng.n] & rng.lowerMask)
		xA := x >> 1
		if (x & 1) != 0 {
			xA = xA ^ a
		}
		rng.MT[i] = rng.MT[(i + rng.m) % rng.n] ^ xA		
	}

	rng.index = 0

	return nil
}

func (rng *Mersenne19937) Stream(n int, b32 bool) (out []int) {
	out = make([]int, n)
	for i := 0; i < n; i++ {
		v, err := rng.Extract(b32)
		if err != nil {
			break
		}
		out[i] = v 
	}
	return out
}
// write out the bits, it is obvious but tedious!
func UnTwist(y int) int {
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

func (rng *Mersenne19937) Splice(arr []int) {
	rng.MT = arr
	rng.index = 0

	return
}
