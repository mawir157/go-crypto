package jmtcrypto

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

	index := n
	
	MT := []int{seed}
	for i := 1; i < n; i++ {
    temp := f * (MT[i-1] ^ (MT[i-1] >> (w-2))) + i
		MT = append(MT, temp & 0xFFFFFFFF)
	}

	lowerMask := (1 << r) - 1
	upperMask := 0 

	return Mersenne19937{w:w, n:n, m:m, r:r, MT:MT, index:index,
	                     lowerMask:lowerMask, upperMask:upperMask}
}

func (rng *Mersenne19937) Extract() (int, error) {
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
	temp := int32(y & 0xFFFFFFFF) 

	return int(temp), nil
}


func (rng *Mersenne19937) twist() error {
	a := 0x9908B0DF
	for i := 0; i < rng.n; i++ {
		x := (rng.MT[i] & rng.upperMask) + (rng.MT[(i+1) % rng.n] & rng.lowerMask)
		xA := x >> 1
		if (x % 2) != 0 {
			xA = xA ^ a
		}
		rng.MT[i] = rng.MT[(i + rng.m) % rng.n] ^ xA		
	}

	rng.index = 0

	return nil
}

func (rng *Mersenne19937) Stream(n int) (out []int) {
	out = make([]int, n)
	for i := 0; i < n; i++ {
		v, err := rng.Extract()
		if err != nil {
			break
		}
		out[i] = v 
	}
	return out
}
