package lms

import (
	"hash"

	"golang.org/x/crypto/sha3"
)

func HashFunc() hash.Hash {
	return sha3.New256()
}
