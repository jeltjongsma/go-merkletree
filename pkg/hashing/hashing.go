package hashing

import "crypto/sha256"

func HashSHA256(b []byte) []byte {
	h := sha256.New()
	h.Write(b)
	return h.Sum(nil)
}

func HashLeaf(l []byte) []byte {
	bytes := append([]byte{0x00}, l...)
	return HashSHA256(bytes)
}

func HashInternal(l, r []byte) []byte {
	bytes := append([]byte{0x01}, l...)
	bytes = append(bytes, r...)
	return HashSHA256(bytes)
}
