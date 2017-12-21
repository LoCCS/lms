package lms

import (
	"bytes"
	"testing"
)

func TestMerge(t *testing.T) {
	left, right := []byte("hello"), []byte("world")

	hashMerged := merge(left, right)

	hashConcatenated := append(left, right...)
	sha := HashFunc()
	sha.Write(hashConcatenated)
	hashMerged2 := sha.Sum(nil)

	if !bytes.Equal(hashMerged, hashMerged2) {
		t.Fatal("failed")
	}
}
