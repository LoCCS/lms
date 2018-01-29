package lms

import (
	"encoding/binary"

	"github.com/LoCCS/lmots"
)

// merge estimates the hash for `I|r|D_INTR|left|right`
func merge(I []byte, r uint32, left, right []byte) []byte {
	sh := HashFunc()

	// key pair ID
	sh.Write(I)

	var buf [4]byte
	// node number
	binary.BigEndian.PutUint32(buf[:], r)
	sh.Write(buf[:])

	// domain separation field
	binary.BigEndian.PutUint16(buf[:2], lmots.D_INTR)
	sh.Write(buf[:2])

	// left child and right child
	sh.Write(left)
	sh.Write(right)

	return sh.Sum(nil)
}

// hashOTSPk estimates the value for a leaf by its bounded
// OTS public key, and it computes the hash value for a LM-OTS pk
// by taking input as `I|r|D_LEAF|ots-pk`,
// where `ots-pk=typecode|I|q|K`
func hashOTSPk(pk *lmots.PublicKey, H uint32) []byte {
	sh := HashFunc()

	// key pair ID
	sh.Write(pk.Opts.I[:])

	var buf [4]byte
	// node number
	nodeIdx := pk.Opts.KeyIdx + (1 << H)
	binary.BigEndian.PutUint32(buf[:], nodeIdx)
	sh.Write(buf[:])

	// domain separation field
	binary.BigEndian.PutUint16(buf[:2], lmots.D_LEAF)
	sh.Write(buf[:2])

	// ots-pk
	sh.Write(pk.Opts.Typecode[:])
	sh.Write(pk.Opts.I[:])
	binary.BigEndian.PutUint32(buf[:], pk.Opts.KeyIdx)
	sh.Write(buf[:])
	sh.Write(pk.K)

	return sh.Sum(nil)
}
