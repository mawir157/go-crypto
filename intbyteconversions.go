package jmtcrypto

import "errors"

func rightRotate(i uint32, n int) uint32 {
	return (i << (32 - n)) +  (i >> n)
}

func leftRotate(i uint32, n int) uint32 {
	return (i >> (32 - n)) + (i << n)
}

func intTo4Bytes(l uint32, be bool) []byte {
	bytes := []byte{0x00, 0x00, 0x00, 0x00}
	for i := 0; i < 4; i++ {
		q := byte(l & 0xff)
		if be {
			bytes[3 - i] = q
		} else {
			bytes[i] = q
		}
		l >>= 8
	}

	return bytes
}

func intTo8Bytes(l int, be bool) []byte {
	bytes := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	for i := 0; i < 8; i++ {
		q := byte(l & 0xff)
		if be {
			bytes[7 - i] = q
		} else {
			bytes[i] = q
		}
		l >>= 8
	}

	return bytes
}

func bytesToInt(arr []byte, be bool) (uint32, error) {
	if len(arr) != 4 {
		return 0, errors.New("not 4 bytes")
	}
	value := uint32(0)
	if be {
		for _, v := range arr {
			value <<= 8
			value += uint32(v)
		}
	} else {
		for i := 3; i >= 0; i-- {
			value <<= 8
			value += uint32(arr[i])
		}
	}


	return value, nil
}

func bytesToIntSlice(arr []byte, be bool) ([]uint32, error) {
	out := []uint32{}
	for i := 0; i < len(arr); i +=4 {
		b, err := bytesToInt(arr[i:i+4], be)
		if err != nil {
			return out, err
		}
		out = append(out, b)
	}

	return out, nil
}

func intSliceToBytes(arr []uint32, be bool) []byte {
	out := []byte{}
	for _, i32 := range arr {
		out = append(out, intTo4Bytes(i32, be)...)
	}

	return out
}