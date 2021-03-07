package main

import (
	"fmt"
	"math/rand"
	"time"
)

func Identity(n int) (Id []Block) {
	for i := 0; i < n; i++ {
		b := make(Block, n / int(INTSIZE))
		b = SetBitAt(b, i)

		Id = append(Id, b)
	}

	return
}

func MatrixPair(n int) ([]Block, []Block) {
	Id    := Identity(n)

	C     := make([]Block, len(Id))
	C_inv := make([]Block, len(Id))

	perm := RandomPermutaion(n)

	// doing this inplace in more trouble than it is worth!
	for i := 0; i < len(perm); i++ {
		C[perm[i]] = Id[i]
		C_inv[i]   = Id[i]
	}

  seed := rand.NewSource(time.Now().UnixNano())
  rng := rand.New(seed)

  swaps := n*n
  is, js:= []int{}, []int{}
  for len(is) < swaps {
		i := rng.Intn(n)
		j := rng.Intn(n)
		if i != j {
			is = append(is, i)
			js = append(js, j)
		}  	
  }

	// apply row operations
	for p := 0; p < len(is); p++ {
		i := is[p]
		j := js[p]
		C[i] = BlockXOR(C[i], C[j])

		i = is[swaps - p - 1]
		j = js[swaps - p - 1]
		C_inv[i] = BlockXOR(C_inv[i], C_inv[j])
	}

	copy(Id, C_inv)

	// doing this inplace in more trouble than it is worth!
	for i := 0; i < len(perm); i++ {
		C_inv[i]   = Id[perm[i]]
	}

	return C, C_inv
	
}

func Column(M []Block, c int) (col Block) {
	ui8 := uint8(0)

	for i := 0; i < len(M); i++ {
		if GetBitAt(M[i], c) {
			ui8 |= 1
		}

		if (i % int(INTSIZE)) == (int(INTSIZE) - 1) {
			col = append(col, ui8)
			ui8 = 0
		}
		ui8 <<= 1
	}
	return 
}

func MatMulMat(M []Block, C []Block) (C_new []Block) {
	C_new = make([]Block, len(M))

	for j, row := range M {
		rowNew := make(Block, len(C[0]))
		// for i := range len(C[0]) {
		for i := 0; i < len(C[0]) * int(INTSIZE); i++ {
			col := Column(C, i)
			if BlockDOT(row, col) {
				rowNew = SetBitAt(rowNew, i)
			}
		}	
		C_new[j] = rowNew
	}

	return
}

func MatMulMatT(M []Block, C []Block) (C_new []Block) {
	C_new = make([]Block, len(M))

	for j, row := range M {
		rowNew := make(Block, len(C) / int(INTSIZE))
		for i, col := range C {
			if BlockDOT(row, col) {
				rowNew = SetBitAt(rowNew, i)
			}
		}	
		C_new[j] = rowNew
	}

	return
}

func MatMulVecL(M []Block, V Block) (Block) {
	V_new := make(Block, len(V))

	for i, row := range M {
		if BlockDOT(row, V) {
			V_new = SetBitAt(V_new, i)
		}
	}

	return V_new
}

func MatMulVecR(V Block, M []Block) (Block) {
	V_new := make(Block, len(V))

	for i := 0; i < len(M[0]) * int(INTSIZE); i++ {
		col := Column(M, i)
		if BlockDOT(V, col) {
			V_new = SetBitAt(V_new, i)
		}
	}	

	return V_new
}

func PrintMatrix(M []Block) {
	for _, r := range M {
		PrintBin(r, true)
	}
	fmt.Printf("\n")
}
