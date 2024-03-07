package jmtcrypto

import "math/rand/v2"

var smallPrimes = []int{2, 3, 5, 7, 11, 13, 17}

func randRange(min, max int) int {
	return rand.IntN(max-min) + min
}

func rmPrimalityCheckRandom(n, rounds int) (bool, error) {
	s := 0
	d := n - 1
	for (d % 2) == 0 {
		d /= 2
		s++
	}

	for k := 0; k < rounds; k++ {
		a := randRange(2, n-2)
		x := 1
		for i := 0; i < d; i++ {
			x *= a
			x %= n
		}

		y := 0
		for i := 0; i < s; i++ {
			y = (x * x) % n

			if (y == 1) && (x != 1) && (x != n-1) {
				return false, nil
			}
			x = y
		}

		if y != 1 {
			return false, nil
		}
	}

	return true, nil
}

func RMPrimalityCheck(n int) (bool, error) {
	if n > 341550071728321 {
		v, err := rmPrimalityCheckRandom(n, 20)
		return v, err
	}

	s := 0
	d := n - 1
	for (d % 2) == 0 {
		d /= 2
		s++
	}

	for _, a := range smallPrimes {
		x := 1
		for i := 0; i < d; i++ {
			x *= a
			x %= n
		}

		y := 0
		for i := 0; i < s; i++ {
			y = (x * x) % n

			if (y == 1) && (x != 1) && (x != n-1) {
				return false, nil
			}
			x = y
		}

		if y != 1 {
			return false, nil
		}
	}

	return true, nil
}

func IsPrime(n int) (bool, error) {
	for _, v := range smallPrimes {
		if n%v == 0 {
			return false, nil
		}
	}

	ret, err := RMPrimalityCheck(n)

	return ret, err
}
