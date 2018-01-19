package lms

import (
	"fmt"

	"github.com/LoCCS/lmots"
	"github.com/LoCCS/lmots/rand"
)

func ExampleVerify() {
	const H = 4
	seed := make([]byte, lmots.N)
	rand.Reader.Read(seed)
	merkleAgent, err := NewMerkleAgent(H, seed)
	if nil != err {
		panic(err)
	}

	msg := make([]byte, lmots.N)
	rand.Reader.Read(msg)
	// what if no more leaf to use in the Merkle agent
	_, sig, err := Sign(merkleAgent, msg)
	if nil != err {
		panic(err)
	}

	fmt.Println(Verify(merkleAgent.Root, msg, sig))
	// Output: true
}
