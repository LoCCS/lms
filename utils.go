package lms

import "github.com/LoCCS/lmots"

// merge estimates the hash for (left||right)
func merge(left, right []byte) []byte {
	h := HashFunc()

	h.Reset()
	h.Write(left)
	h.Write(right)

	return h.Sum(nil)
}

// HashPk computes the hash value for a LM-OTS public key
func HashPk(pk *lmots.PublicKey) []byte {
	h := HashFunc()

	//h.Write(pk.I)
	//h.Write(lmotscore.D_LEAF)
	h.Write(pk.K)

	return h.Sum(nil)
}
