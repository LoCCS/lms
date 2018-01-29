package lms

import "errors"

// Collections of common errors while running MerkleAgent
var (
	ErrInvalidHeight = errors.New("H should be larger than 1")              // merkle tree should be of height at least 2
	ErrOutOfKeys     = errors.New("key pairs on the tree are totally used") // no more keys to use
)
