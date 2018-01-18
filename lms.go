package lms

import (
	"bytes"
	"errors"

	"github.com/LoCCS/lmots"
	"github.com/LoCCS/lmots/rand"
)


// MerkleSig is the container for the signature generated
// according to MSS
type MerkleSig struct {
	Leaf   uint32
	LeafPk *lmots.PublicKey
	LMSig  *lmots.Sig

	Auth [][]byte
}

// Sign produces a Merkle signature
func Sign(agent *MerkleAgent, hash []byte) (*lmots.PrivateKey, *MerkleSig, error) {
	merkleSig := new(MerkleSig)
	merkleSig.Leaf = agent.keyItr.Offset()

	offset := agent.keyItr.Offset()
	if offset >= (1 << agent.H) {
		return nil, nil, errors.New("key pairs on the tree are totally used")
	}

	sk, err := agent.keyItr.Next()
	if err != nil {
		return nil, nil, err
	}
	merkleSig.LMSig, err = lmots.Sign(rand.Reader, sk, hash)
	if nil != err {
		return nil, nil, errors.New("unexpected error occurs during signing")
	}

	// fill in the public key deriving leaf
	merkleSig.LeafPk = (&sk.PublicKey).Clone()

	//fmt.Println("Leaf:", merkleSig.Leaf+(1<<agent.H))
	//fmt.Printf("LeafPk: %x\n", agent.nodeHouse[0])
	// copy the auth path
	merkleSig.Auth = make([][]byte, len(agent.auth))
	for i := range agent.auth {
		merkleSig.Auth[i] = make([]byte, len(agent.auth[i]))
		copy(merkleSig.Auth[i], agent.auth[i])

		//fmt.Printf("%v: %x\n", i, agent.auth[i])
	}

	// update auth path
	agent.Traverse()
	offset = agent.keyItr.Offset()
	err = nil
	if offset == (1<<agent.H)-1 {
		err = errors.New("Warning: this is the last signature")
	}

	return sk, merkleSig, err
}

// Verify verifies a Merkle signature
func Verify(root []byte, hash []byte, merkleSig *MerkleSig) bool {
	if (nil == merkleSig) || (!lmots.Verify(merkleSig.LeafPk, hash, merkleSig.LMSig)) {
		//fmt.Println("merkleSig: \n", merkleSig)
		//fmt.Println("***ots failed")
		return false
	}
	//fmt.Printf("root: %x\n", root)

	H := len(merkleSig.Auth)
	// index of node in current height h
	// node number for siblings of Auth[h]
	idx := merkleSig.Leaf + (1 << uint32(H))
	//fmt.Println("Leaf: ", idx)

	parentHash := hashOTSPk(merkleSig.LeafPk, uint32(H))
	//fmt.Printf("LeafPk: %x\n", parentHash)
	for h := 0; h < H; h++ {
		/*hashFunc.Reset()
		if 1 == idx%2 { // idx is odd, i.e., a right node
			hashFunc.Write(merkleSig.Auth[h])
			hashFunc.Write(parentHash)
		} else {
			hashFunc.Write(parentHash)
			hashFunc.Write(merkleSig.Auth[h])
		}*/
		// level up
		//parentHash = hashFunc.Sum(nil)
		if 1 == idx%2 {
			parentHash = merge(idx/2, merkleSig.Auth[h], parentHash)
		} else {
			parentHash = merge(idx/2, parentHash, merkleSig.Auth[h])
		}
		//fmt.Printf("%v: %x\n", h, merkleSig.Auth[h])
		//fmt.Printf("%x\n", parentHash)

		idx = idx >> 1
	}

	return bytes.Equal(parentHash, root)
}