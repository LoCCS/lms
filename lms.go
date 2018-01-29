package lms

import (
	"bytes"

	"github.com/LoCCS/lmots"
	"github.com/LoCCS/lmots/rand"
)

// MerkleSig is the container for the signature generated
// according to LMS
type MerkleSig struct {
	Opts  *lmots.LMOpts
	LMSig *lmots.Sig // OTS signature

	Auth [][]byte
}

// Sign produces a Merkle signature
func Sign(agent *MerkleAgent, hash []byte) (*lmots.PrivateKey, *MerkleSig, error) {
	merkleSig := new(MerkleSig)

	if agent.Exhausted() {
		return nil, nil, ErrOutOfKeys
	}

	sk, err := agent.keyItr.Next()
	if err != nil {
		return nil, nil, err
	}

	merkleSig.LMSig, err = lmots.Sign(rand.Reader, sk, hash)
	if nil != err {
		return nil, nil, err
	}

	// fill in the public key deriving leaf
	merkleSig.Opts = sk.PublicKey.Opts.Clone()

	// copy the auth path
	merkleSig.Auth = make([][]byte, len(agent.auth))
	for i := range agent.auth {
		merkleSig.Auth[i] = make([]byte, len(agent.auth[i]))
		copy(merkleSig.Auth[i], agent.auth[i])
	}

	// update auth path
	agent.Traverse()

	return sk, merkleSig, nil
}

// Verify verifies a Merkle signature
func Verify(root []byte, hash []byte, merkleSig *MerkleSig) bool {
	leafPk := &lmots.PublicKey{
		Opts: merkleSig.Opts,
	}

	{
		var err error
		if leafPk.K, err = lmots.RecoverK(merkleSig.Opts, hash, merkleSig.LMSig); nil != err {
			return false
		}
	}

	H := len(merkleSig.Auth)
	// index of node in current height h
	idx := merkleSig.Opts.KeyIdx + (1 << uint32(H))

	parentHash := hashOTSPk(leafPk, uint32(H))
	for h := 0; h < H; h++ {
		// level up
		if 1 == idx%2 {
			parentHash = merge(leafPk.Opts.I[:], idx/2, merkleSig.Auth[h], parentHash)
		} else {
			parentHash = merge(leafPk.Opts.I[:], idx/2, parentHash, merkleSig.Auth[h])
		}

		idx = idx >> 1
	}

	return bytes.Equal(parentHash, root)
}
