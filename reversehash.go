package jmtcrypto

import (
	"fmt"
)

func matchSlices(arr1, arr2 []byte) bool {
	for i, v := range arr1 {
		if arr2[i] != v {
			return false
		}
	}
	return true
}

func allZero(arr []byte) bool {
	for _, v := range arr {
		if v != 0x00 {
			return false
		}
	}
	return true
}

func ReverseHash(initial, target []byte, h HashFunction) []byte {
	n := len(target)
	if n > 16 {
		target = target[:16]
	}

	test := h.Hash(initial)
	if matchSlices(target[:n], test[:n]) {
		return initial
	}

	counter := []byte{0x00}
	for {
		temp := append(initial, counter...)
		test = h.Hash(temp)
		if matchSlices(target[:n], test[:n]) {
			fmt.Printf("added %d bytes\n", len(counter))
			return temp
		}
		counter = incrementCTR(counter)
		if allZero(counter) {
			counter = append(counter, 0x00)
		}
	}
}
