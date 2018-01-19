package lms

import (
	"bytes"
	"encoding/gob"

	"github.com/LoCCS/lms/container/stack"
)

// thsEx is the exporting template of TreeHashStack
type thsEx struct {
	Leaf      uint32
	LeafUpper uint32
	H         uint32
	NodeStack []*Node
}

// GobEncode customizes the Gob encoding scheme for TreeHashStack
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

// GobDecode customizes the Gob decoding scheme for TreeHashStack
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
		ths.nodeStack.Push(&Node{Height: n.Height, Nu: n.Nu, Index: n.Index})
	}

	return nil
}
