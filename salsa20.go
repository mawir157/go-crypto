package jmtcrypto

import "fmt"

var diagonal, _ = ParseFromAscii("expand 32-byte k", false)

func salsaBlock(key, nonce []byte) []byte {
	sBlock := make([]byte, 64)
	copy(sBlock[0:4],   diagonal[0:4])
	copy(sBlock[4:8],   key[0:4])
	copy(sBlock[8:12],  key[4:8])
	copy(sBlock[12:16], key[8:12])

	copy(sBlock[16:20], key[12:16])
	copy(sBlock[20:24], diagonal[4:8])
	copy(sBlock[24:28], nonce[0:4])
	copy(sBlock[28:32], nonce[4:8])

	// copy(sBlock[32:36], counter[0:4])
	// copy(sBlock[36:40], counter[4:8])
	copy(sBlock[40:44], diagonal[8:12])
	copy(sBlock[44:48], key[16:20])

	copy(sBlock[48:52], key[20:24])
	copy(sBlock[52:56], key[24:28])
	copy(sBlock[56:60], key[28:32])
	copy(sBlock[60:64], diagonal[12:16])

	return sBlock
}

func SalsaEncode(key, nonce, msg []byte) []byte {
	out := []byte{}
	hash := MakeSHA256()
	key = hash.Hash(key)
fmt.Println(ParseToBase64(key))

	n := len(msg)
	// need to pad msg to multiple of 64
	diff := 64 - (len(msg) % 64)
	pad := make([]byte, diff)
	msg = append(msg, pad...)

	counter := []byte{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}

	sBlock := salsaBlock(key, nonce)
	// set counter
	copy(sBlock[32:36], counter[0:4])
	copy(sBlock[36:40], counter[4:8])

	for i := 0; i < len(msg); i += 64 {
		copy(sBlock[32:36], counter[0:4])
		copy(sBlock[36:40], counter[4:8])

		intBlock, _ := BytesToIntSlice(sBlock, false) // this consists four uint32s
		eBlock := salsaFunction(intBlock)
		byteBlock := intSliceToBytes(eBlock, false)

		byteBlock = byteStreamXOR(msg[i:i+64], byteBlock)
		out = append(out, byteBlock...)
		counter = incrementCTR(counter)
	}

	return out[:n]
}

func salsaFunction(in []uint32) (out []uint32) {
	out = make([]uint32, len(in))
	x := make([]uint32, len(in))

	copy(x, in)
	copy(out, in)

	rounds := 20
	for i := 0; i < rounds; i += 2 {
		// Odd round
		qr(x,  0,  4,  8, 12)	// column 1
		qr(x,  5,  9, 13,  1)	// column 2
		qr(x, 10, 14,  2,  6)	// column 3
		qr(x, 15,  3,  7, 11)	// column 4
		// Even round
		qr(x,  0,  1,  2,  3)	// row 1
		qr(x,  5,  6,  7,  4)	// row 2
		qr(x, 10, 11,  8,  9)	// row 3
		qr(x, 15, 12, 13, 14)	// row 4
	}

	for i, v := range x {
		out[i] += v
	}

	return out
}

func qr(x []uint32, a,b,c,d int) {
	x[b] = x[b] ^ LeftRotate(x[a] + x[d],  7)
	x[c] = x[c] ^ LeftRotate(x[b] + x[a],  9)
	x[d] = x[d] ^ LeftRotate(x[c] + x[b], 13)
	x[a] = x[a] ^ LeftRotate(x[d] + x[c], 18)

	return
}

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
	qr(testVector,  0,  1,  2,  3)	// row 1
	qr(testVector,  5,  6,  7,  4)	// row 2
	qr(testVector, 10, 11,  8,  9)	// row 3
	qr(testVector, 15, 12, 13, 14)	// row 4
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
	qr(testVector,  0,  1,  2,  3)	// row 1
	qr(testVector,  5,  6,  7,  4)	// row 2
	qr(testVector, 10, 11,  8,  9)	// row 3
	qr(testVector, 15, 12, 13, 14)	// row 4
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
	qr(testVector,  0,  4,  8, 12)	// column 1
	qr(testVector,  5,  9, 13,  1)	// column 2
	qr(testVector, 10, 14,  2,  6)	// column 3
	qr(testVector, 15,  3,  7, 11)	// column 4
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
	qr(testVector,  0,  4,  8, 12)	// column 1
	qr(testVector,  5,  9, 13,  1)	// column 2
	qr(testVector, 10, 14,  2,  6)	// column 3
	qr(testVector, 15,  3,  7, 11)	// column 4
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
	qr(testVector,  0,  4,  8, 12)	// column 1
	qr(testVector,  5,  9, 13,  1)	// column 2
	qr(testVector, 10, 14,  2,  6)	// column 3
	qr(testVector, 15,  3,  7, 11)	// column 4
	qr(testVector,  0,  1,  2,  3)	// row 1
	qr(testVector,  5,  6,  7,  4)	// row 2
	qr(testVector, 10, 11,  8,  9)	// row 3
	qr(testVector, 15, 12, 13, 14)	// row 4
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
	qr(testVector,  0,  4,  8, 12)	// column 1
	qr(testVector,  5,  9, 13,  1)	// column 2
	qr(testVector, 10, 14,  2,  6)	// column 3
	qr(testVector, 15,  3,  7, 11)	// column 4
	qr(testVector,  0,  1,  2,  3)	// row 1
	qr(testVector,  5,  6,  7,  4)	// row 2
	qr(testVector, 10, 11,  8,  9)	// row 3
	qr(testVector, 15, 12, 13, 14)	// row 4
	fmt.Printf("%08x\n", testVector)
	fmt.Printf("%08x\n", expected)
	fmt.Println()

	salsaBytes := []byte{211, 159, 13, 115, 76, 55, 82, 183, 3, 117, 222, 37, 191, 187, 234, 136,
	                     49, 237, 179, 48, 1, 106, 178, 219, 175, 199, 166, 48, 86, 16, 179, 207,
	                     31, 240, 32, 63, 15, 83, 93, 161, 116, 147, 48, 113, 238, 55, 204, 36,
	                     79, 201, 235, 79, 3, 81, 156, 47, 203, 26, 244, 243, 88, 118, 104, 54}
	salsaInts, _ := BytesToIntSlice(salsaBytes, false)
	salsaInts = salsaFunction(salsaInts)
	salsaBytes = intSliceToBytes(salsaInts, false)

	fmt.Printf("%d\n", salsaBytes)
	// fmt.Printf("%08x\n", expected)
	fmt.Println()
}

