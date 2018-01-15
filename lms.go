package lms

import (
	"bytes"
	"errors"
	"math"

	"github.com/LoCCS/lmots"
	"github.com/LoCCS/lmots/rand"
)

// MerkleAgent implements a agent working
// according to the Merkle signature scheme
type MerkleAgent struct {
	H              uint32
	auth           [][]byte
	root           []byte
	nodeHouse      [][]byte
	treeHashStacks []*TreeHashStack
	keyItr         *KeyIterator
}

// NewMerkleAgent makes a fresh Merkle signing routine
// by running the generate key and setup procedure
func NewMerkleAgent(H uint32, seed []byte) (*MerkleAgent, error) {
	if H < 2 {
		return nil, errors.New("H should be larger than 1")
	}

	agent := new(MerkleAgent)
	agent.H = H
	agent.auth = make([][]byte, H)
	agent.nodeHouse = make([][]byte, 1<<H)
	agent.treeHashStacks = make([]*TreeHashStack, H)
	agent.keyItr = NewKeyIterator(seed)
	export, err := agent.keyItr.Serialize()
	if nil != err {
		return nil, err
	}

	for i := 0; i < (1 << H); i++ {
		sk, err := agent.keyItr.Next()
		if err != nil {
			return nil, err
		}
		//agent.nodeHouse[i] = HashPk(&sk.PublicKey)
		agent.nodeHouse[i] = hashOTSPk(&sk.PublicKey, agent.H)
	}
	globalStack := NewTreeHashStack(0, H)
	for h := uint32(0); h < H; h++ {
		globalStack.Update(1, agent.nodeHouse)
		agent.treeHashStacks[h] = NewTreeHashStack(0, h)

		agent.treeHashStacks[h].nodeStack.Push(globalStack.Top())
		agent.treeHashStacks[h].SetLeaf(1 << h)

		globalStack.Update((1<<(h+1))-1, agent.nodeHouse)
		agent.auth[h] = make([]byte, len(globalStack.Top().nu))
		copy(agent.auth[h], globalStack.Top().nu)
	}

	globalStack.Update(1, agent.nodeHouse)
	agent.root = make([]byte, len(globalStack.Top().nu))
	copy(agent.root, globalStack.Top().nu)

	//agent.keyItr.Init(export)
	if err := agent.keyItr.Deserialize(export); nil != err {
		return nil, err
	}
	return agent, nil
}

// refreshAuth updates auth path for next use
func (agent *MerkleAgent) refreshAuth() {
	//nextLeaf := agent.NumLeafUsed + 1
	nextLeaf := agent.keyItr.Offset()
	for h := uint32(0); h < agent.H; h++ {
		pow2Toh := uint32(1 << h)
		// nextLeaf % 2^h == 0
		if 0 == nextLeaf&(pow2Toh-1) {
			copy(agent.auth[h], agent.treeHashStacks[h].Top().nu)
			startingLeaf := (nextLeaf + pow2Toh) ^ pow2Toh
			agent.treeHashStacks[h].Init(startingLeaf, h)

		}
	}
}

// refreshTreeHashStacks updates stack for next use
func (agent *MerkleAgent) refreshTreeHashStacks() {
	numOp := 2*agent.H - 1
	for i := uint32(0); i < numOp; i++ {
		globalLowest := uint32(math.MaxUint32)
		var focus uint32
		for h := uint32(0); h < agent.H; h++ {
			localLowest := agent.treeHashStacks[h].LowestTailHeight()
			if localLowest < globalLowest {
				globalLowest = localLowest
				focus = h
			}
		}
		agent.treeHashStacks[focus].Update(1, agent.nodeHouse)
	}
}

// Traverse updates both auth path and retained stack for next use
func (agent *MerkleAgent) Traverse() {
	agent.refreshAuth()
	agent.refreshTreeHashStacks()
}

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

// return the verification root
func (agent *MerkleAgent) Root() []byte {
	return agent.root
}

// SerializeSecret encodes all the secret data which shall be encrypted
func (agent *MerkleAgent) SerializeSecretKey() []byte {
	secretData, _ := agent.keyItr.Serialize()
	return secretData
}

// GetLeaf returns the index of next leaf to use
func (agent *MerkleAgent) GetLeaf() uint32 {
	return agent.keyItr.Offset()
}
