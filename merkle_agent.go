package lms

import (
	"bytes"
	"encoding/gob"
	"errors"
	"math"
)

// MerkleAgent implements a agent working
// according to the Merkle signature scheme
type MerkleAgent struct {
	H              uint32
	auth           [][]byte
	Root           []byte
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
		agent.nodeHouse[i] = hashOTSPk(&sk.PublicKey, agent.H)
	}
	globalStack := NewTreeHashStack(0, H)
	for h := uint32(0); h < H; h++ {
		globalStack.Update(agent.keyItr.LMOpts.I[:], 1, agent.nodeHouse)
		agent.treeHashStacks[h] = NewTreeHashStack(0, h)

		agent.treeHashStacks[h].nodeStack.Push(globalStack.Top())
		agent.treeHashStacks[h].SetLeaf(1 << h)

		globalStack.Update(agent.keyItr.LMOpts.I[:], (1<<(h+1))-1, agent.nodeHouse)
		agent.auth[h] = make([]byte, len(globalStack.Top().Nu))
		copy(agent.auth[h], globalStack.Top().Nu)
	}

	globalStack.Update(agent.keyItr.LMOpts.I[:], 1, agent.nodeHouse)
	agent.Root = make([]byte, len(globalStack.Top().Nu))
	copy(agent.Root, globalStack.Top().Nu)

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
			copy(agent.auth[h], agent.treeHashStacks[h].Top().Nu)
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
		//agent.treeHashStacks[focus].Update(1, agent.nodeHouse)
		agent.treeHashStacks[focus].Update(agent.keyItr.LMOpts.I[:], 1, agent.nodeHouse)
	}
}

// Traverse updates both auth path and retained stack for next use
func (agent *MerkleAgent) Traverse() {
	agent.refreshAuth()
	agent.refreshTreeHashStacks()
}

// SerializeSecretKey encodes all the secret data which shall be encrypted
func (agent *MerkleAgent) SerializeSecretKey() []byte {
	secretData, _ := agent.keyItr.Serialize()
	return secretData
}

// LeafIdx returns the index of next leaf to use
func (agent *MerkleAgent) LeafIdx() uint32 {
	return agent.keyItr.Offset()
}

type merkleAgentEx struct {
	H              uint32
	Auth           [][]byte
	Root           []byte
	NodeHouse      [][]byte
	TreeHashStacks []*TreeHashStack
}

// GobEncode customizes the Gob encoding for MerkleAgent
func (agent *MerkleAgent) GobEncode() ([]byte, error) {
	agentGob := &merkleAgentEx{
		H:              agent.H,
		Auth:           agent.auth,
		Root:           agent.Root,
		NodeHouse:      agent.nodeHouse,
		TreeHashStacks: agent.treeHashStacks,
		//KeyItr:         agent.keyItr,
	}

	buf := new(bytes.Buffer)
	if err := gob.NewEncoder(buf).Encode(agentGob); nil != err {
		return nil, err
	}

	return buf.Bytes(), nil
}

// GobDecode customizes the Gob decoding for MerkleAgent
func (agent *MerkleAgent) GobDecode(data []byte) error {
	agentGob := new(merkleAgentEx)

	if err := gob.NewDecoder(bytes.NewBuffer(data)).Decode(agentGob); nil != err {
		return err
	}

	agent.H = agentGob.H
	agent.auth = agentGob.Auth
	agent.Root = agentGob.Root
	agent.nodeHouse = agentGob.NodeHouse
	agent.treeHashStacks = agentGob.TreeHashStacks

	return nil
}

// Serialize encodes all the information about the merkle tree
// that can be stored as plaintext
func (agent *MerkleAgent) Serialize() ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := gob.NewEncoder(buf).Encode(agent); nil != err {
		return nil, err
	}

	return buf.Bytes(), nil
}

// RebuildMerkleAgent restores the merkle agent from serialized bytes
// and secret bytes
func (agent *MerkleAgent) RebuildMerkleAgent(data []byte, secret []byte) error {
	if err := gob.NewDecoder(bytes.NewBuffer(data)).Decode(agent); nil != err {
		return err
	}

	agent.keyItr = new(KeyIterator)
	return agent.keyItr.Deserialize(secret)
}
