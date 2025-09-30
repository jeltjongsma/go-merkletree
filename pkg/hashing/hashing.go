package hashing

import "crypto/sha256"

func HashSHA256(b []byte) []byte {
	h := sha256.New()
	h.Write(b)
	return h.Sum(nil)
}
