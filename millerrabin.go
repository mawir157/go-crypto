package jmtcrypto

import "math/rand/v2"

func randRange(min, max int) int {
	return rand.IntN(max-min) + min
}

func RMPrimalityCheck(n, rounds int) (bool, error) {
	s := 0
	d := n - 1
	for (d % 2) == 0 {
		d /= 2
		s++
	}

	for k := 0; k < rounds; k++ {
		a := randRange(2, n-2)
		x := (a * d) % n

		y := 0
		for i := 0; i < s; i++ {
			y = (x * x) % n

			if (y == 1) && (x != 1) && (x != n-1) {
				return false, nil
			}
		}

		if y != 1 {
			return false, nil
		}
	}

	return true, nil
}
