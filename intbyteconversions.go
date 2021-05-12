package jmtcrypto

// import "errors"

func RightRotate(i uint32, n int) uint32 {
	return (i << (32 - n)) +  (i >> n)
}

func LeftRotate(i uint32, n int) uint32 {
	return (i >> (32 - n)) + (i << n)
}

func IntTo4Bytes(l uint32) []byte {
	bytes := []byte{0x00, 0x00, 0x00, 0x00}
	for i := 0; i < 4; i++ {
		q := byte(l & 0xff)
		bytes[3 - i] = q
		l >>= 8
	}

	return bytes
}

func IntTo8Bytes(l int) []byte {
	bytes := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	for i := 0; i < 8; i++ {
		q := byte(l & 0xff)
		bytes[7 - i] = q
		l >>= 8
	}

	return bytes
}

func BytesToInt(arr []byte) (uint32, error) {
	// if len(arr) != 4 {
	// 	return 0, errors.New("Not 4 bytes")
	// }
	value := uint32(0)
	for _, v := range arr {
		value <<= 8
		value += uint32(v)
	}

	return value, nil
}

func BytesToIntSlice(arr []byte) ([]uint32, error) {
	out := []uint32{}
	for i := 0; i < len(arr); i +=4 {
		b, _ := BytesToInt(arr[i:i+4])
		out = append(out, b)
	}

	return out, nil
}

func intSliceToBytes(arr []uint32) []byte {
	out := []byte{}
	for _, i32 := range arr {
		out = append(out, IntTo4Bytes(i32)...)
	}

	return out
}