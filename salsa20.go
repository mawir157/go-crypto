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

		intBlock, _ := BytesToIntSlice(sBlock) // this consists four uint32s
		eBlock := salsaFunction(intBlock)
		byteBlock := intSliceToBytes(eBlock)

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

	rounds := 20
	for i := 0; i < rounds; i += 2 {
		// Odd round
		qr(x,  0,  4,  8, 12);	// column 1
		qr(x,  5,  9, 13,  1);	// column 2
		qr(x, 10, 14,  2,  6);	// column 3
		qr(x, 15,  3,  7, 11);	// column 4
		// Even round
		qr(x,  0,  1,  2,  3);	// row 1
		qr(x,  5,  6,  7,  4);	// row 2
		qr(x, 10, 11,  8,  9);	// row 3
		qr(x, 15, 12, 13, 14);	// row 4		
	}

	for i := 0; i < 16; i++ {
		out[i] = x[i] + in[i]
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
	key := []byte{0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                  0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,
              	  0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,
                  0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38}

    nonce := []byte{0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08}

    sBlock := salsaBlock(key, nonce) 

	counter := []byte{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}

	// test qr
	testqr, _ := BytesToIntSlice(sBlock)
fmt.Println(testqr)
	qr(testqr,  0,  1,  2,  3)
fmt.Println(testqr)
fmt.Println("--------------------------------------------------------------")
	for i := 0; i < 2; i++ {
fmt.Println("counter:")
fmt.Println(counter)
		copy(sBlock[32:36], counter[0:4])
		copy(sBlock[36:40], counter[4:8])
fmt.Println("sBlock:")
fmt.Println(sBlock)
		intBlock, _ := BytesToIntSlice(sBlock) // this consists four uint32s
fmt.Println("intBlock:")
fmt.Println(intBlock)
		eBlock := salsaFunction(intBlock)
fmt.Println("eBlock:")
fmt.Println(eBlock)
		byteBlock := intSliceToBytes(eBlock)
fmt.Println("byteBlock:")
fmt.Println(byteBlock)
fmt.Println("=====================================================================")
		// eBlock = byteStreamXOR(msg[i:i+bc.BlockSize()], eBlock)
		counter = incrementCTR(counter)
	}

}

