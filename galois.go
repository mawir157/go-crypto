package jmtcrypto

// TOTALLY UNTESTED AND LIKELY TO BE BROKEN!
func galoisMultiply(poly1 []byte, poly2 []byte) []byte {
	if len(poly1) == 16 {
		panic("Galois multiplication only implement for 128 bit field")
	}
	Z := Uint128{0, 0}
	V, _ := BytesToInt128(poly1, false)
	Y, _ := BytesToInt128(poly2, false)
	R := uint64(225)
	R = (R << 56)

	ui64 := uint64(1)
	for i := 0; i < 128; i++ {
		block64 := i / 64
		index := i % 64
		mask := ui64 << (15 - index)
		value := Y[block64] & mask
		if value != 0 {
			Z[0] = Z[0] ^ V[0]
			Z[1] = Z[1] ^ V[1]
		}
		V = RightRotate128(V, 1)
		if (Z[1] & 1) != 0 {
			Z[0] = Z[0] & R
		}
	}

	return Int128ToBytes(V, false)
}
