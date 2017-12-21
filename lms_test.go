package lms

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/LoCCS/lmots"
	"github.com/LoCCS/lmots/rand"
)

const (
	H = 8 // the height of the merkle tree
)

func TestLMS(t *testing.T) {
	//seed, err := rand.RandSeed()
	seed := make([]byte, lmots.N)
	rand.Reader.Read(seed)
	agentStart := time.Now()
	merkleAgent, err := NewMerkleAgent(H, seed)
	agentTime := time.Since(agentStart)

	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("Time on new merkle Agent with height %v : %v\n", H, agentTime)

	var signSum time.Duration
	var verifySum time.Duration
	var maxsig time.Duration
	var maxver time.Duration
	success := 0
	failure := 0
	for i := 0; i < 1<<H+2; i++ {

		if i%1837 == 0 {
			fmt.Printf("Success %v, failure %v\n", success, failure)
			mBytes := merkleAgent.Serialize()
			sBytes := merkleAgent.SerializeSecret()
			merkleAgent = RebuildMerkleAgent(mBytes, sBytes)
		}

		//	message, err := rand.RandSeed()
		message := make([]byte, lmots.N)
		rand.Reader.Read(message)
		signStart := time.Now()
		_, sig, err := Sign(merkleAgent, message)
		signTime := time.Since(signStart)
		if err != nil {
			fmt.Println(err)
			if !strings.Contains(err.Error(), "Warning") {
				continue
			}
		}
		signSum += signTime
		if signTime > maxsig {
			maxsig = signTime
			fmt.Printf("Currently max sig time: %v\n", maxsig)
		}
		//fmt.Printf("Sign in %v\n", signTime)
		//fmt.Println("Leaf: ", sig.Leaf)
		//fmt.Println("sign ", time.Now())
		verifyStart := time.Now()
		result := Verify(merkleAgent.Root(), message, sig)
		verifyTime := time.Since(verifyStart)
		verifySum += verifyTime
		//fmt.Printf("Verify in %v\n", verifyTime)
		if verifyTime > maxver {
			maxver = verifyTime
			fmt.Printf("Currently max verify time: %v\n", maxver)
		}
		if result {
			success++
		} else {
			failure++
		}

	}
	fmt.Println()
	fmt.Printf("Success %v, failure %v\n", success, failure)
	fmt.Printf("Merkle agent building time %v : %v\n", H, agentTime)
	fmt.Printf("Average signature time: %v\n", signSum/(1<<H))
	fmt.Printf("Max signature time: %v\n", maxsig)
	fmt.Printf("Average verification time: %v\n", verifySum/(1<<H))
	fmt.Printf("Max verify time: %v\n", maxver)

}

func TestMSSStd(t *testing.T) {
	seed := make([]byte, lmots.N)
	rand.Reader.Read(seed)
	merkleAgent, err := NewMerkleAgent(H, seed)
	if nil != err {
		t.Fatal("unexpected error in setting up")
	}

	// make a random message
	msg := make([]byte, lmots.N)
	rand.Reader.Read(msg)

	//t.Logf("msg: %x\n", msg)
	_, sig, err := Sign(merkleAgent, msg)
	if nil != err {
		t.Fatalf("error in signing %x", msg)
	}

	//t.Logf("merkleSig: %+v\n", sig)

	if !Verify(merkleAgent.Root(), msg, sig) {
		t.Fatal("verification failed")
	}
}
