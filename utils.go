package lms

import (
	"encoding/binary"

	"github.com/LoCCS/lmots"
)

// merge estimates the hash for (left||right)
func merge(left, right []byte) []byte {
	h := HashFunc()

	h.Reset()
	h.Write(left)
	h.Write(right)

	return h.Sum(nil)
}

// hashOTSPk estimates the value for a leaf by its bounded
// OTS public key
func hashOTSPk(pk *lmots.PublicKey, H uint32) []byte {
	sh := HashFunc()

	// key pair ID
	sh.Write(pk.I[:])

	var buf [4]byte
	// node number
	nodeIdx := pk.KeyIdx() + 1 + (1 << H)
	binary.BigEndian.PutUint32(buf[:], nodeIdx)
	sh.Write(buf[:])

	// domain separation field
	binary.BigEndian.PutUint16(buf[:2], lmots.D_LEAF)
	sh.Write(buf[:2])

	// ots-pk
	pktype := pk.Type()
	sh.Write(pktype[:])
	sh.Write(pk.I[:])
	binary.BigEndian.PutUint32(buf[:], pk.KeyIdx())
	sh.Write(buf[:])
	sh.Write(pk.K)

	return sh.Sum(nil)
}
