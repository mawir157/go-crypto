package dh

import (
	"math/big"
)

type DiffieHellman struct {
	p, g big.Int
}

func DiffHell(p, g big.Int) DiffieHellman {
	return DiffieHellman{p:p, g:g}
}

func ParseToBigInt(s string) (i big.Int) {
	i.SetString(s, 10)

	return 
}

func ParseToBigIntHex(s string) (i big.Int) {
	i.SetString(s, 16)

	return 
}

func (dh DiffieHellman) ToPublic(a *big.Int) (A big.Int) {
	A.Exp(&dh.g, a, &dh.p)

	return
}

func (dh DiffieHellman) ToShared(B, a *big.Int) (S big.Int) {
	S.Exp(B, a, &dh.p)

	return
}