package combinatorics

import BS "../bitset"

func Choose(n, k uint) uint {
	if k > n {
		panic("Choose: k > n")
	}
	if k < 0 {
		panic("Choose: k < 0")
	}
	if n <= 1 || k == 0 || n == k {
		return 1
	}
	if newK := n - k; newK < k {
		k = newK
	}
	if k == 1 {
		return n
	}
	// Our return value, and this allows us to skip the first iteration.
	ret := uint(n - k + 1)
	for i, j := ret+1, uint(2); j <= k; i, j = i+1, j+1 {
		ret = ret * i / j
	}
	return ret
}

func GetWedges(set []BS.Block, depth uint) []BS.Block {
		ones := make([]uint8, len(set[0]))
		for i := range ones {
		    ones[i] = 255
		}

    return GetWedgesHelper(set, depth, 0, ones, []BS.Block{})
}

func GetWedgesHelper(set []BS.Block, depth uint, start uint,
	                    product BS.Block, accum []BS.Block) []BS.Block {
    if depth == 0 {
        return append(accum, product)
    } else {
        for i := start; i <= uint(len(set)) - depth; i++ {
            accum = GetWedgesHelper(set, depth - 1, i + 1,
            	                      BS.BlockAND(product, set[i]), accum)
        }
        return accum
    }
}

// Set Difference: A - B
func Difference(a, b []uint) (diff []uint) {
	m := make(map[uint]bool)

	for _, item := range b {
		m[item] = true
	}

	for _, item := range a {
		if _, ok := m[item]; !ok {
			diff = append(diff, item)
		}
	}
	return
}

func InvertIndices(m uint, is [][]uint) ([][]uint) {
	all := []uint{}
	for i := uint(1); i <= m; i++ {
		all = append(all, i)
	}	

	for i, v := range is {
		is[i] = Difference(all, v)
	}

	return is
}

func AlternatingVector(run, n uint) (v []uint8) {
	ui8 := uint8(0)
	runcount := uint(0)
	runflag := true
	for i := uint(0); i < n; i++ {
		if runflag {
			ui8 |= 1
		}

		if (i % BS.INTSIZE) == (BS.INTSIZE - 1) {
			v = append(v, ui8)
			ui8 = 0
		}
		ui8 <<= 1

		runcount += 1
		if runcount == run {
			runflag = !runflag
			runcount = 0
		}
	}
	return 
}

func rPool(p uint, n []uint, c []uint, cc [][]uint) [][]uint {
    if len(n) == 0 || p <= 0 {
        return cc
    }
    p--
    for i := range n {
        r := make([]uint, len(c)+1)
        copy(r, c)
        r[len(r)-1] = n[i]
        if p == 0 {
            cc = append(cc, r)
        }
        cc = rPool(p, n[i+1:], r, cc)
    }
    return cc
}

func Pool(p uint, n []uint) [][]uint {
    return rPool(p, n, nil, nil)
}