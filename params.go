package lms

import (
	"hash"

	"golang.org/x/crypto/sha3"
)

// HashFunc returns a consistent hash function for usage
// across the whole project
func HashFunc() hash.Hash {
	return sha3.New256()
}
