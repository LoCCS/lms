package lms

import (
	"bytes"
	"errors"
	"math"

	"encoding/binary"

	"github.com/LoCCS/lmots"
	"github.com/LoCCS/lmots/rand"
)

// MerkleAgent implements a agent working
//	according to the Merkle signature scheme
type MerkleAgent struct {
	H              uint32
	auth           [][]byte
	root           []byte
	nodeHouse      [][]byte
	treeHashStacks []*TreeHashStack
	keyItr         *KeyIterator
}

// NewMerkleAgent makes a fresh Merkle signing routine
//	by running the generate key and setup procedure
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
	export := agent.keyItr.Serialize()

	for i := 0; i < (1 << H); i++ {
		sk, err := agent.keyItr.Next()
		if err != nil {
			return nil, err
		}
		//agent.nodeHouse[i] = HashPk(&sk.PublicKey)
		agent.nodeHouse[i] = hashOTSPk(&sk.PublicKey, agent.H)
	}
	globalStack := NewTreeHashStack(0, H+1)
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
	agent.keyItr.Init(export)
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
//	according to MSS
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

	// TODO: adapt for *WtnOpts
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
	//merkleSig.LeafPk = &sk.PublicKey
	merkleSig.LeafPk = (&sk.PublicKey).Clone()

	// copy the auth path
	merkleSig.Auth = make([][]byte, len(agent.auth))
	for i := range agent.auth {
		merkleSig.Auth[i] = make([]byte, len(agent.auth[i]))
		copy(merkleSig.Auth[i], agent.auth[i])
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
		//fmt.Println("***ots failed")
		return false
	}

	H := len(merkleSig.Auth)
	// index of node in current height h
	idx := merkleSig.Leaf
	//hashFunc := config.HashFunc()
	hashFunc := HashFunc()

	//parentHash := HashPk(merkleSig.LeafPk)
	parentHash := hashOTSPk(merkleSig.LeafPk, uint32(H))
	for h := 0; h < H; h++ {
		hashFunc.Reset()
		if 1 == idx%2 { // idx is odd, i.e., a right node
			hashFunc.Write(merkleSig.Auth[h])
			hashFunc.Write(parentHash)
		} else {
			hashFunc.Write(parentHash)
			hashFunc.Write(merkleSig.Auth[h])
		}
		// level up
		parentHash = hashFunc.Sum(nil)
		idx = idx >> 1
	}

	return bytes.Equal(parentHash, root)
}

// return the verification root
func (agent *MerkleAgent) Root() []byte {
	return agent.root
}

//Serialize encodes all the information about the merkle tree that can be stored as plaintext
func (agent *MerkleAgent) Serialize() []byte {
	//size := config.Size
	size := lmots.N
	ret := make([]byte, 4+4+size+int(agent.H)*size)
	binary.LittleEndian.PutUint32(ret[0:4], agent.H)
	binary.LittleEndian.PutUint32(ret[4:8], uint32(size))
	copy(ret[8:8+size], agent.root[:])
	offset := 8 + size
	for i := 0; i < int(agent.H); i++ {
		copy(ret[offset:offset+size], agent.auth[i][:])
		offset += size
	}
	for i := 0; i < int(agent.H); i++ {
		treeHashBytes := agent.treeHashStacks[i].Serialize()
		ret = append(ret, treeHashBytes...)
	}
	for _, node := range agent.nodeHouse {
		ret = append(ret, node...)
	}
	return ret
}

//SerializeSecret encodes all the secret data which shall be encrypted
func (agent *MerkleAgent) SerializeSecret() []byte {
	return agent.keyItr.Serialize()
}

//RebuildMerkleAgent restores the merkle agent from serialized bytes and secret bytes
func RebuildMerkleAgent(plain []byte, secret []byte) *MerkleAgent {
	agent := &MerkleAgent{}
	seed := make([]byte, lmots.N)
	agent.keyItr = NewKeyIterator(seed)
	agent.keyItr.Init(secret)
	agent.H = binary.LittleEndian.Uint32(plain[0:4])
	hashSize := binary.LittleEndian.Uint32(plain[4:8])
	root := plain[8 : 8+hashSize]
	agent.root = root
	offset := 8 + hashSize
	agent.auth = make([][]byte, agent.H)
	for i := 0; i < int(agent.H); i++ {
		agent.auth[i] = plain[offset : offset+hashSize]
		offset += hashSize
	}
	agent.treeHashStacks = make([]*TreeHashStack, agent.H)
	for i := 0; i < int(agent.H); i++ {
		stackSize := binary.LittleEndian.Uint32(plain[offset : offset+4])
		elementSize := binary.LittleEndian.Uint32(plain[offset+4 : offset+8])
		stackBytes := plain[offset : offset+20+stackSize*elementSize]
		agent.treeHashStacks[i] = RebuildTreeHashStack(stackBytes)
		offset += 20 + stackSize*elementSize
	}
	agent.nodeHouse = make([][]byte, 1<<agent.H)
	for i := 0; i < (1 << agent.H); i++ {
		agent.nodeHouse[i] = plain[offset : offset+hashSize]
		offset += hashSize
	}
	return agent
}
