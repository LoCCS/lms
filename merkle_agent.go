package lms

import (
	"bytes"
	"encoding/gob"
)

type merkleAgentEx struct {
	H              uint32
	Auth           [][]byte
	Root           []byte
	NodeHouse      [][]byte
	TreeHashStacks []*TreeHashStack
	//KeyItr         *KeyIterator
}

func (agent *MerkleAgent) GobEncode() ([]byte, error) {
	agentGob := &merkleAgentEx{
		H:              agent.H,
		Auth:           agent.auth,
		Root:           agent.root,
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

func (agent *MerkleAgent) GobDecode(data []byte) error {
	agentGob := new(merkleAgentEx)

	if err := gob.NewDecoder(bytes.NewBuffer(data)).Decode(agentGob); nil != err {
		return err
	}

	agent.H = agentGob.H
	agent.auth = agentGob.Auth
	agent.root = agentGob.Root
	agent.nodeHouse = agentGob.NodeHouse
	agent.treeHashStacks = agentGob.TreeHashStacks
	//agent.keyItr = agentGob.KeyItr

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
