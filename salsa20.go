package jmtcrypto

import "fmt"

func salsaBlock(key, nonce []byte) []byte {
	diagonal := []byte{}
	if len(key) == 32 {
		// do nothing
		diagonal, _ = ParseFromASCII("expand 32-byte k", false)
	} else if len(key) == 16 {
		key = append(key, key...)
		diagonal, _ = ParseFromASCII("expand 16-byte k", false)
	} else {
		fmt.Printf("Error! Key length = %d\n", len(key))
	}

	sBlock := make([]byte, 64)
	copy(sBlock[0:4], diagonal[0:4])
	copy(sBlock[4:8], key[0:4])
	copy(sBlock[8:12], key[4:8])
	copy(sBlock[12:16], key[8:12])

	copy(sBlock[16:20], key[12:16])
	copy(sBlock[20:24], diagonal[4:8])
	copy(sBlock[24:28], nonce[0:4])
	copy(sBlock[28:32], nonce[4:8])

	copy(sBlock[32:36], nonce[8:12])
	copy(sBlock[36:40], nonce[12:16])
	copy(sBlock[40:44], diagonal[8:12])
	copy(sBlock[44:48], key[16:20])

	copy(sBlock[48:52], key[20:24])
	copy(sBlock[52:56], key[24:28])
	copy(sBlock[56:60], key[28:32])
	copy(sBlock[60:64], diagonal[12:16])

	return sBlock
}

// SalsaEncode -
func SalsaEncode(key, nonce, msg []byte) []byte {
	out := []byte{}

	n := len(msg)
	// need to pad msg to multiple of 64
	diff := 64 - (len(msg) % 64)
	pad := make([]byte, diff)
	msg = append(msg, pad...)

	counter := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	for i := 0; i < len(msg); i += 64 {
		nonceCounter := append(nonce, counter...)
		sBlock := salsaBlock(key, nonceCounter)

		intBlock, _ := bytesToIntSlice(sBlock, false)
		eBlock := salsaFunction(intBlock)
		byteBlock := intSliceToBytes(eBlock, false)

		byteBlock = byteStreamXOR(msg[i:i+64], byteBlock)
		out = append(out, byteBlock...)
		counter = incrementCTR(counter)
	}

	return out[:n]
}

// SalsaDecode -
func SalsaDecode(key, nonce, msg []byte) ([]byte, error) {
	out := SalsaEncode(key, nonce, msg)

	return out, nil
}

func salsaFunction(in []uint32) (out []uint32) {
	out = make([]uint32, len(in))
	x := make([]uint32, len(in))

	copy(x, in)
	copy(out, in)

	rounds := 20
	for i := 0; i < rounds; i += 2 {
		// Odd round
		qr(x, 0, 4, 8, 12)  // column 1
		qr(x, 5, 9, 13, 1)  // column 2
		qr(x, 10, 14, 2, 6) // column 3
		qr(x, 15, 3, 7, 11) // column 4
		// Even round
		qr(x, 0, 1, 2, 3)     // row 1
		qr(x, 5, 6, 7, 4)     // row 2
		qr(x, 10, 11, 8, 9)   // row 3
		qr(x, 15, 12, 13, 14) // row 4
	}

	for i, v := range x {
		out[i] += v
	}

	return out
}

func qr(x []uint32, a, b, c, d int) {
	x[b] = x[b] ^ leftRotate(x[a]+x[d], 7, 32)
	x[c] = x[c] ^ leftRotate(x[b]+x[a], 9, 32)
	x[d] = x[d] ^ leftRotate(x[c]+x[b], 13, 32)
	x[a] = x[a] ^ leftRotate(x[d]+x[c], 18, 32)
}

func chaChaBlock(key, nonce []byte) []byte {
	diagonal := []byte{}
	if len(key) == 32 {
		// do nothing
		diagonal, _ = ParseFromASCII("expand 32-byte k", false)
	} else if len(key) == 16 {
		key = append(key, key...)
		diagonal, _ = ParseFromASCII("expand 16-byte k", false)
	} else {
		fmt.Printf("Error! Key length = %d\n", len(key))
	}

	sBlock := make([]byte, 64)
	copy(sBlock[0:16], diagonal)
	copy(sBlock[16:48], key)
	copy(sBlock[48:64], nonce)

	return sBlock
}

func chaChaFunction(in []uint32) (out []uint32) {
	out = make([]uint32, len(in))
	x := make([]uint32, len(in))

	copy(x, in)
	copy(out, in)

	rounds := 20
	for i := 0; i < rounds; i += 2 {
		// Odd round
		qrChaCha(x, 0, 4, 8, 12)  // column 1
		qrChaCha(x, 1, 5, 9, 13)  // column 2
		qrChaCha(x, 2, 6, 10, 14) // column 3
		qrChaCha(x, 3, 7, 11, 15) // column 4
		// Even round
		qrChaCha(x, 0, 5, 10, 15) // row 1
		qrChaCha(x, 1, 6, 11, 12) // row 2
		qrChaCha(x, 2, 7, 8, 13)  // row 3
		qrChaCha(x, 3, 4, 9, 14)  // row 4
	}

	for i, v := range x {
		out[i] += v
	}

	return out
}

func qrChaCha(x []uint32, a, b, c, d int) {
	x[a] += x[b]
	x[d] = leftRotate(x[d]^x[a], 16, 32)
	x[c] += x[d]
	x[b] = leftRotate(x[b]^x[c], 12, 32)
	x[a] += x[b]
	x[d] = leftRotate(x[d]^x[a], 8, 32)
	x[c] += x[d]
	x[b] = leftRotate(x[b]^x[c], 7, 32)
}

// ChaChaEncode -
func ChaChaEncode(key, nonce, msg []byte) []byte {
	out := []byte{}

	n := len(msg)
	// need to pad msg to multiple of 64
	diff := 64 - (len(msg) % 64)
	pad := make([]byte, diff)
	msg = append(msg, pad...)

	counter := []byte{0x00, 0x00, 0x00, 0x00}
	for i := 0; i < len(msg); i += 64 {
		nonceCounter := append(counter, nonce...)
		sBlock := chaChaBlock(key, nonceCounter)

		intBlock, _ := bytesToIntSlice(sBlock, false)
		eBlock := chaChaFunction(intBlock)
		byteBlock := intSliceToBytes(eBlock, false)

		byteBlock = byteStreamXOR(msg[i:i+64], byteBlock)
		out = append(out, byteBlock...)
		counter = incrementCTR(counter)
	}

	return out[:n]
}

// ChaChaDecode -
func ChaChaDecode(key, nonce, msg []byte) ([]byte, error) {
	out := ChaChaEncode(key, nonce, msg)

	return out, nil
}

// TestSalsa -
func TestSalsa() {
	// test quarter round
	testVector := []uint32{0x00000000, 0x00000000, 0x00000000, 0x00000000}
	qr(testVector, 0, 1, 2, 3)
	expected := []uint32{0x00000000, 0x00000000, 0x00000000, 0x00000000}
	fmt.Printf("%08x\n", testVector)
	fmt.Printf("%08x\n", expected)
	fmt.Println()

	testVector = []uint32{0x00000001, 0x00000000, 0x00000000, 0x00000000}
	qr(testVector, 0, 1, 2, 3)
	expected = []uint32{0x08008145, 0x00000080, 0x00010200, 0x20500000}
	fmt.Printf("%08x\n", testVector)
	fmt.Printf("%08x\n", expected)
	fmt.Println()

	testVector = []uint32{0xd3917c5b, 0x55f1c407, 0x52a58a7a, 0x8f887a3b}
	qr(testVector, 0, 1, 2, 3)
	expected = []uint32{0x3e2f308c, 0xd90a8f36, 0x6ab2a923, 0x2883524c}
	fmt.Printf("%08x\n", testVector)
	fmt.Printf("%08x\n", expected)
	fmt.Println()

	testVector = []uint32{0xe7e8c006, 0xc4f9417d, 0x6479b4b2, 0x68c67137}
	qr(testVector, 0, 1, 2, 3)
	expected = []uint32{0xe876d72b, 0x9361dfd5, 0xf1460244, 0x948541a3}
	fmt.Printf("%08x\n", testVector)
	fmt.Printf("%08x\n", expected)
	fmt.Println()

	// test row round
	testVector = []uint32{0x00000001, 0x00000000, 0x00000000, 0x00000000,
		0x00000001, 0x00000000, 0x00000000, 0x00000000,
		0x00000001, 0x00000000, 0x00000000, 0x00000000,
		0x00000001, 0x00000000, 0x00000000, 0x00000000}
	expected = []uint32{0x08008145, 0x00000080, 0x00010200, 0x20500000,
		0x20100001, 0x00048044, 0x00000080, 0x00010000,
		0x00000001, 0x00002000, 0x80040000, 0x00000000,
		0x00000001, 0x00000200, 0x00402000, 0x88000100}
	qr(testVector, 0, 1, 2, 3)     // row 1
	qr(testVector, 5, 6, 7, 4)     // row 2
	qr(testVector, 10, 11, 8, 9)   // row 3
	qr(testVector, 15, 12, 13, 14) // row 4
	fmt.Printf("%08x\n", testVector)
	fmt.Printf("%08x\n", expected)
	fmt.Println()

	testVector = []uint32{0x08521bd6, 0x1fe88837, 0xbb2aa576, 0x3aa26365,
		0xc54c6a5b, 0x2fc74c2f, 0x6dd39cc3, 0xda0a64f6,
		0x90a2f23d, 0x067f95a6, 0x06b35f61, 0x41e4732e,
		0xe859c100, 0xea4d84b7, 0x0f619bff, 0xbc6e965a}
	expected = []uint32{0xa890d39d, 0x65d71596, 0xe9487daa, 0xc8ca6a86,
		0x949d2192, 0x764b7754, 0xe408d9b9, 0x7a41b4d1,
		0x3402e183, 0x3c3af432, 0x50669f96, 0xd89ef0a8,
		0x0040ede5, 0xb545fbce, 0xd257ed4f, 0x1818882d}
	qr(testVector, 0, 1, 2, 3)     // row 1
	qr(testVector, 5, 6, 7, 4)     // row 2
	qr(testVector, 10, 11, 8, 9)   // row 3
	qr(testVector, 15, 12, 13, 14) // row 4
	fmt.Printf("%08x\n", testVector)
	fmt.Printf("%08x\n", expected)
	fmt.Println()

	// test column round
	testVector = []uint32{0x00000001, 0x00000000, 0x00000000, 0x00000000,
		0x00000001, 0x00000000, 0x00000000, 0x00000000,
		0x00000001, 0x00000000, 0x00000000, 0x00000000,
		0x00000001, 0x00000000, 0x00000000, 0x00000000}
	expected = []uint32{0x10090288, 0x00000000, 0x00000000, 0x00000000,
		0x00000101, 0x00000000, 0x00000000, 0x00000000,
		0x00020401, 0x00000000, 0x00000000, 0x00000000,
		0x40a04001, 0x00000000, 0x00000000, 0x00000000}
	qr(testVector, 0, 4, 8, 12)  // column 1
	qr(testVector, 5, 9, 13, 1)  // column 2
	qr(testVector, 10, 14, 2, 6) // column 3
	qr(testVector, 15, 3, 7, 11) // column 4
	fmt.Printf("%08x\n", testVector)
	fmt.Printf("%08x\n", expected)
	fmt.Println()

	testVector = []uint32{0x08521bd6, 0x1fe88837, 0xbb2aa576, 0x3aa26365,
		0xc54c6a5b, 0x2fc74c2f, 0x6dd39cc3, 0xda0a64f6,
		0x90a2f23d, 0x067f95a6, 0x06b35f61, 0x41e4732e,
		0xe859c100, 0xea4d84b7, 0x0f619bff, 0xbc6e965a}
	expected = []uint32{0x8c9d190a, 0xce8e4c90, 0x1ef8e9d3, 0x1326a71a,
		0x90a20123, 0xead3c4f3, 0x63a091a0, 0xf0708d69,
		0x789b010c, 0xd195a681, 0xeb7d5504, 0xa774135c,
		0x481c2027, 0x53a8e4b5, 0x4c1f89c5, 0x3f78c9c8}
	qr(testVector, 0, 4, 8, 12)  // column 1
	qr(testVector, 5, 9, 13, 1)  // column 2
	qr(testVector, 10, 14, 2, 6) // column 3
	qr(testVector, 15, 3, 7, 11) // column 4
	fmt.Printf("%08x\n", testVector)
	fmt.Printf("%08x\n", expected)
	fmt.Println()

	// test double round
	testVector = []uint32{0x00000001, 0x00000000, 0x00000000, 0x00000000,
		0x00000000, 0x00000000, 0x00000000, 0x00000000,
		0x00000000, 0x00000000, 0x00000000, 0x00000000,
		0x00000000, 0x00000000, 0x00000000, 0x00000000}
	expected = []uint32{0x8186a22d, 0x0040a284, 0x82479210, 0x06929051,
		0x08000090, 0x02402200, 0x00004000, 0x00800000,
		0x00010200, 0x20400000, 0x08008104, 0x00000000,
		0x20500000, 0xa0000040, 0x0008180a, 0x612a8020}
	qr(testVector, 0, 4, 8, 12)    // column 1
	qr(testVector, 5, 9, 13, 1)    // column 2
	qr(testVector, 10, 14, 2, 6)   // column 3
	qr(testVector, 15, 3, 7, 11)   // column 4
	qr(testVector, 0, 1, 2, 3)     // row 1
	qr(testVector, 5, 6, 7, 4)     // row 2
	qr(testVector, 10, 11, 8, 9)   // row 3
	qr(testVector, 15, 12, 13, 14) // row 4
	fmt.Printf("%08x\n", testVector)
	fmt.Printf("%08x\n", expected)
	fmt.Println()

	testVector = []uint32{0xde501066, 0x6f9eb8f7, 0xe4fbbd9b, 0x454e3f57,
		0xb75540d3, 0x43e93a4c, 0x3a6f2aa0, 0x726d6b36,
		0x9243f484, 0x9145d1e8, 0x4fa9d247, 0xdc8dee11,
		0x054bf545, 0x254dd653, 0xd9421b6d, 0x67b276c1}
	expected = []uint32{0xccaaf672, 0x23d960f7, 0x9153e63a, 0xcd9a60d0,
		0x50440492, 0xf07cad19, 0xae344aa0, 0xdf4cfdfc,
		0xca531c29, 0x8e7943db, 0xac1680cd, 0xd503ca00,
		0xa74b2ad6, 0xbc331c5c, 0x1dda24c7, 0xee928277}
	qr(testVector, 0, 4, 8, 12)    // column 1
	qr(testVector, 5, 9, 13, 1)    // column 2
	qr(testVector, 10, 14, 2, 6)   // column 3
	qr(testVector, 15, 3, 7, 11)   // column 4
	qr(testVector, 0, 1, 2, 3)     // row 1
	qr(testVector, 5, 6, 7, 4)     // row 2
	qr(testVector, 10, 11, 8, 9)   // row 3
	qr(testVector, 15, 12, 13, 14) // row 4
	fmt.Printf("%08x\n", testVector)
	fmt.Printf("%08x\n", expected)
	fmt.Println()

	sKey := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216}
	sNonce := []byte{101, 102, 103, 104, 105, 106, 107, 108,
		109, 110, 111, 112, 113, 114, 115, 116}
	sBlock := salsaBlock(sKey, sNonce)
	fmt.Printf("%d\n", sBlock)

	intBlock, _ := bytesToIntSlice(sBlock, false) // this consists four uint32s
	eBlock := salsaFunction(intBlock)
	byteBlock := intSliceToBytes(eBlock, false)
	fmt.Printf("%d\n", byteBlock)

	sKey = []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	sBlock = salsaBlock(sKey, sNonce)
	fmt.Printf("%d\n", sBlock)

	intBlock, _ = bytesToIntSlice(sBlock, false) // this consists four uint32s
	eBlock = salsaFunction(intBlock)
	byteBlock = intSliceToBytes(eBlock, false)
	fmt.Printf("%d\n", byteBlock)

	// fmt.Printf("%d\n", XORdBlocks)
	// fmt.Printf("%08x\n", expected)
	fmt.Println()
}

// TestChaCha -
func TestChaCha() {
	key := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}
	nonce := []byte{0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a,
		0x00, 0x00, 0x00, 0x00}
	ctr := []byte{0x01, 0x00, 0x00, 0x00}
	nonceCounter := append(ctr, nonce...)
	sBlock := chaChaBlock(key, nonceCounter)
	intBlock, _ := bytesToIntSlice(sBlock, false)
	// fmt.Printf("%08x", intBlock)
	for i, v := range intBlock {
		fmt.Printf("%08x", v)
		if i%4 == 3 {
			fmt.Printf("\n")
		} else {
			fmt.Printf(" ")
		}
	}
	fmt.Printf("\n")
	intBlock = chaChaFunction(intBlock)
	for i, v := range intBlock {
		fmt.Printf("%08x", v)
		if i%4 == 3 {
			fmt.Printf("\n")
		} else {
			fmt.Printf(" ")
		}
	}
}
