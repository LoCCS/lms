package lms

import (
	"fmt"
	"testing"
	"time"

	"github.com/LoCCS/lmots"
	"github.com/LoCCS/lmots/rand"
)

const (
	H = 16 // the height of the merkle tree
)

func TestLMSApp(t *testing.T) {
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
	for i := 0; i < 1<<H+1; i++ {

		if i%1837 == 0 {
			fmt.Printf("Success %v, failure %v\n", success, failure)
			mBytes, _ := merkleAgent.Serialize()
			sBytes := merkleAgent.SerializeSecretKey()
			merkleAgent.Rebuild(mBytes, sBytes)
		}

		message := make([]byte, lmots.N)
		rand.Reader.Read(message)
		signStart := time.Now()

		_, sigraw, err := Sign(merkleAgent, message)

		signTime := time.Since(signStart)
		if err != nil {
			if err == ErrOutOfKeys {
				if (1 << H) != i {
					t.Fatalf("invalid i: want %v, got %v", (1 << H), i)
				}
				fmt.Printf("%s at i = %v", err, i)
				break
			} else {
				t.Fatal(err)
			}
		}

		sigData, err := sigraw.Serialize()
		if nil != err {
			t.Fatal(err)
		}
		sig := new(MerkleSig)
		if err := sig.Deserialize(sigData); nil != err {
			t.Fatal(err)
		}

		signSum += signTime
		if signTime > maxsig {
			maxsig = signTime
			fmt.Printf("Currently max sig time: %v\n", maxsig)
		}

		verifyStart := time.Now()

		result := Verify(merkleAgent.Root, message, sig)

		verifyTime := time.Since(verifyStart)
		verifySum += verifyTime

		if verifyTime > maxver {
			maxver = verifyTime
			fmt.Printf("Currently max verify time: %v\n", maxver)
		}
		if result {
			success++
		} else {
			failure++
			return
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

func TestLMSStdOps(t *testing.T) {
	const H = 3
	seed := make([]byte, lmots.N)
	rand.Reader.Read(seed)
	merkleAgent, err := NewMerkleAgent(H, seed)
	if nil != err {
		t.Fatal("unexpected error in setting up")
	}

	// make a random message
	msg := make([]byte, lmots.N)
	rand.Reader.Read(msg)

	_, sig, err := Sign(merkleAgent, msg)
	if nil != err {
		t.Fatalf("error in signing %x", msg)
	}

	if !Verify(merkleAgent.Root, msg, sig) {
		t.Fatal("verification failed")
	}
}
