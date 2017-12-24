package lms

import (
	"encoding/binary"
	"fmt"
	"math"

	"github.com/LoCCS/lmots"
	"github.com/LoCCS/lms/container/stack"
)

// Node is a node in the Merkle tree
type Node struct {
	height uint32
	nu     []byte
	index  uint32
}

// String generates the string representation of node
func (node *Node) String() string {
	return fmt.Sprintf("{height: %v, index: %v}", node.height, node.index)
}

// TreeHashStack is a stack tracing the running state
// of the tree hash algo
type TreeHashStack struct {
	leaf      uint32       // zero-based index of starting leaf
	leafUpper uint32       // the global upper bound of leaves for this tree hash instance
	height    uint32       // height of the targeted Merkle tree
	nodeStack *stack.Stack // stacks store nodes for each Merkle sub-tree of height from 0 to H-1
}

func (th *TreeHashStack) SetLeaf(leaf uint32) {
	th.leaf = leaf
}

// NewTreeHashStack makes a new tree hash instance
func NewTreeHashStack(startingLeaf, h uint32) *TreeHashStack {
	treeHashStack := new(TreeHashStack)
	treeHashStack.Init(startingLeaf, h)
	return treeHashStack
}

// Init initializes the tree hash instance to target specific height
// and the range of leaves
func (th *TreeHashStack) Init(startingLeaf, h uint32) error {

	th.leaf, th.leafUpper, th.height = startingLeaf, startingLeaf+(1<<h), h
	//th.leaf, th.height = startingLeaf, h
	th.nodeStack = stack.New() // clear up the stack

	return nil
}

// IsCompleted checks if the tree hash instance has completed
func (th *TreeHashStack) IsCompleted() bool {
	return (th.leaf >= th.leafUpper) && (th.nodeStack.Peek().(*Node).height == th.height)
}

// LowestTailHeight returns the lowest height of tail nodes
// in this tree hash instance
func (th *TreeHashStack) LowestTailHeight() uint32 {
	if th.nodeStack.Empty() {
		return th.height
	}
	if th.IsCompleted() {
		return math.MaxUint32
	}
	return th.Top().height
}

// Top returns the node in the top of the stack
func (th *TreeHashStack) Top() *Node {
	if th.nodeStack.Empty() {
		return nil
	}

	return th.nodeStack.Peek().(*Node)
}

// Update executes numOp updates on the instance, and
// add on the new leaf derived by keyItr if necessary
func (th *TreeHashStack) Update(numOp uint32, nodeHouse [][]byte) {
	//H := uint32(bits.Len32(uint32()) - 1)
	numLeaf := uint32(len(nodeHouse))
	//fmt.Println("H:", H)
	for (numOp > 0) && !th.IsCompleted() {
		// may have nodes at the same height to merge
		if th.nodeStack.Len() >= 2 {
			e1, e2 := th.nodeStack.Peek2()
			node1 := e1.(*Node)
			node2 := e2.(*Node)

			// merge the nodes at the same height
			if node1.height == node2.height {
				th.nodeStack.Pop()
				th.nodeStack.Pop()

				//*
				th.nodeStack.Push(&Node{
					height: node1.height + 1,
					nu:     merge(node2.index/2, node2.nu, node1.nu),
					index:  node2.index / 2,
				})
				//*/
				//th.nodeStack.Push(mergeNode(node2, node1))

				//fmt.Printf("h: %v, index: %v, nu: %x\n", node1.height+1,
				//	node2.index/2, merge(node2.index/2, node2.nu, node1.nu))
				numOp--
				continue
			}
		}

		// invoke key generator to make a new leaf and
		//	add the new leaf to S
		//if th.leaf >= uint32(len(nodeHouse)) {
		if th.leaf >= numLeaf {
			//th.nodeStack.Push(&Node{0, nodeHouse[0]})
			// dummy node
			th.nodeStack.Push(&Node{
				height: 0,
				nu:     nodeHouse[0],
				index:  numLeaf,
			})
			//fmt.Println("wooo")
		} else {
			//th.nodeStack.Push(&Node{0, nodeHouse[th.leaf]})
			th.nodeStack.Push(&Node{
				height: 0,
				nu:     nodeHouse[th.leaf],
				index:  th.leaf + numLeaf,
			})
			//fmt.Printf("h: %v, index: %v, nu: %x, leaf: %v\n", 0,
			//	th.leaf+(1<<H), nodeHouse[th.leaf], th.leaf)
		}
		th.leaf++
		numOp--
	}
}

// Serialize encodes the Treehashstack as
// +---------------------------------------------------------+
// |	stackLen||elementSize||element||element||...||element| |
// +---------------------------------------------------------+
// elements are put from bottom to top
func (th *TreeHashStack) Serialize() []byte {
	stackSize := uint32(th.nodeStack.Len())
	//elementSize := uint32(4 + lmots.N)
	elementSize := uint32(4 + lmots.N + 4)
	ret := make([]byte, 20+stackSize*elementSize)
	binary.LittleEndian.PutUint32(ret[0:], stackSize)
	binary.LittleEndian.PutUint32(ret[4:], elementSize)
	binary.LittleEndian.PutUint32(ret[8:], th.leaf)
	binary.LittleEndian.PutUint32(ret[12:], th.leafUpper)
	binary.LittleEndian.PutUint32(ret[16:], th.height)

	vs := th.nodeStack.ValueSlice()
	offset := 20
	for i := 0; i < th.nodeStack.Len(); i++ {
		binary.LittleEndian.PutUint32(ret[offset:], vs[i].(*Node).height)
		offset += 4
		copy(ret[offset:], vs[i].(*Node).nu)
		//offset += config.Size
		offset += lmots.N
		// add by sammy
		binary.LittleEndian.PutUint32(ret[offset:], vs[i].(*Node).index)
		offset += 4
	}

	return ret
}

// RebuildTreeHashStack restores the TreeHashStack from serialized bytes
func RebuildTreeHashStack(stackBytes []byte) *TreeHashStack {
	th := &TreeHashStack{}

	th.leaf = binary.LittleEndian.Uint32(stackBytes[8:])
	th.leafUpper = binary.LittleEndian.Uint32(stackBytes[12:])
	th.height = binary.LittleEndian.Uint32(stackBytes[16:])

	stackSize := binary.LittleEndian.Uint32(stackBytes[0:])
	elementSize := binary.LittleEndian.Uint32(stackBytes[4:])
	//hashSize := int(elementSize) - 4
	hashSize := int(elementSize) - 4 - 4

	offset := 20
	th.nodeStack = stack.New()
	for i := 0; i < int(stackSize); i++ {
		height := binary.LittleEndian.Uint32(stackBytes[offset : offset+4])
		offset += 4
		nu := stackBytes[offset : offset+hashSize]
		offset += hashSize
		index := binary.LittleEndian.Uint32(stackBytes[offset : offset+4])
		offset += 4
		node := &Node{
			height: height,
			nu:     nu,
			index:  index,
		}
		th.nodeStack.Push(node)
	}

	return th
}
