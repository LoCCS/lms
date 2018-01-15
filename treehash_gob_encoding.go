package lms

import (
	"bytes"
	"encoding/gob"

	"github.com/LoCCS/lms/container/stack"
)

type nodeEx struct {
	Height uint32
	Nu     []byte
	Index  uint32
}

func (node Node) GobEncode() ([]byte, error) {
	nodeGob := &nodeEx{
		Height: node.height,
		Nu:     node.nu,
		Index:  node.index,
	}

	buf := new(bytes.Buffer)
	if err := gob.NewEncoder(buf).Encode(nodeGob); nil != err {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (node *Node) GobDecode(data []byte) error {
	nodeGob := new(nodeEx)

	if err := gob.NewDecoder(bytes.NewBuffer(data)).Decode(nodeGob); nil != err {
		return err
	}

	node.height = nodeGob.Height
	node.nu = nodeGob.Nu
	node.index = nodeGob.Index

	return nil
}

// thsEx is the exporting template of TreeHashStack
type thsEx struct {
	Leaf      uint32
	LeafUpper uint32
	H         uint32
	NodeStack []*Node
}

func (ths TreeHashStack) GobEncode() ([]byte, error) {
	thsGob := &thsEx{
		Leaf:      ths.leaf,
		LeafUpper: ths.leafUpper,
		H:         ths.height,
	}

	values := ths.nodeStack.ValueSlice()
	thsGob.NodeStack = make([]*Node, len(values))
	for i := range values {
		thsGob.NodeStack[i] = values[i].(*Node)
	}

	buf := new(bytes.Buffer)
	if err := gob.NewEncoder(buf).Encode(thsGob); nil != err {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (ths *TreeHashStack) GobDecode(data []byte) error {
	thsGob := new(thsEx)

	if err := gob.NewDecoder(bytes.NewBuffer(data)).Decode(thsGob); nil != err {
		return err
	}

	ths.leaf = thsGob.Leaf
	ths.leafUpper = thsGob.LeafUpper
	ths.height = thsGob.H
	ths.nodeStack = stack.New()

	for _, n := range thsGob.NodeStack {
		ths.nodeStack.Push(&Node{height: n.height, nu: n.nu, index: n.index})
	}

	return nil
}
