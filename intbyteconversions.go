package jmtcrypto

import "errors"

type Uint128 [2]uint64 // x = x[0] * 2^64 + x[1]

func rightRotate[T uint32 | uint64](i T, n int, size int) T {
	return (i << (size - n)) + (i >> n)
}

// TODO
func RightRotate128(i Uint128, n int) Uint128 {
	j0, j1 := (i[0] << (64 - n)), (i[0] >> n)
	k0, k1 := (i[1] << (64 - n)), (i[1] >> n)

	return Uint128{j0 + k1, j1 + k0}
}

func leftRotate[T uint32 | uint64](i T, n int, size int) T {
	return (i >> (size - n)) + (i << n)
}

func intTo4Bytes(l uint32, be bool) []byte {
	bytes := []byte{0x00, 0x00, 0x00, 0x00}
	for i := 0; i < 4; i++ {
		q := byte(l & 0xff)
		if be {
			bytes[3-i] = q
		} else {
			bytes[i] = q
		}
		l >>= 8
	}

	return bytes
}

func uintTo8Bytes(l uint64, be bool) []byte {
	bytes := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	for i := 0; i < 8; i++ {
		q := byte(l & 0xff)
		if be {
			bytes[7-i] = q
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
			bytes[7-i] = q
		} else {
			bytes[i] = q
		}
		l >>= 8
	}

	return bytes
}

func uint64To8Bytes(l uint64, be bool) []byte {
	bytes := make([]byte, 8)
	for i := 0; i < 8; i++ {
		q := byte(l & 0xff)
		if be {
			bytes[7-i] = q
		} else {
			bytes[i] = q
		}
		l >>= 8
	}

	return bytes
}

func bytesToInt32(arr []byte, be bool) (uint32, error) {
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

func bytesToInt64(arr []byte, be bool) (uint64, error) {
	if len(arr) != 8 {
		return 0, errors.New("not 8 bytes")
	}
	value := uint64(0)
	if be {
		for _, v := range arr {
			value <<= 8
			value += uint64(v)
		}
	} else {
		for i := 7; i >= 0; i-- {
			value <<= 8
			value += uint64(arr[i])
		}
	}

	return value, nil
}

func bytesToIntSlice(arr []byte, be bool) ([]uint32, error) {
	out := []uint32{}
	for i := 0; i < len(arr); i += 4 {
		b, err := bytesToInt32(arr[i:i+4], be)
		if err != nil {
			return out, err
		}
		out = append(out, b)
	}

	return out, nil
}

func bytesToInt64Slice(arr []byte, be bool) ([]uint64, error) {
	out := []uint64{}
	for i := 0; i < len(arr); i += 8 {
		b, err := bytesToInt64(arr[i:i+8], be)
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

func BytesToInt128(arr []byte, be bool) (Uint128, error) {
	if len(arr) != 16 {
		return [2]uint64{0, 0}, errors.New("not 16 bytes")
	}

	value := [2]uint64{0, 0}

	if be {
		for i, v := range arr {
			value[i/8] <<= 8
			value[i/8] += uint64(v)
		}
	} else {
		for i := 7; i >= 0; i-- {
			value[i/8] <<= 8
			value[i/8] += uint64(arr[i])
		}
	}

	return value, nil
}

func Int128ToBytes(l Uint128, be bool) []byte {
	bytes := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	for i := 0; i < 16; i++ {
		q := byte(l[i/8] & 0xff)
		if be {
			bytes[15-i] = q
		} else {
			bytes[i] = q
		}
		l[i/8] >>= 8
	}

	return bytes
}
