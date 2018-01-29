package lms

import (
	"testing"

	"github.com/LoCCS/lmots"
	"github.com/LoCCS/lmots/rand"
)

//func BenchmarkLMSSetup(b *testing.B) {
func BenchmarkNewMerkleAgent(b *testing.B) {
	const H = 16
	seed := make([]byte, lmots.N)
	rand.Reader.Read(seed)

	for i := 0; i < b.N; i++ {
		if _, err := NewMerkleAgent(H, seed); nil != err {
			b.Fatalf("unexpected error in  NewMerkleAgent(%v,%x)", H, seed)
		}
	}
}

func BenchmarkLMSStdOps(b *testing.B) {
	const H = 8
	seed := make([]byte, lmots.N)
	rand.Reader.Read(seed)
	merkleAgent, err := NewMerkleAgent(H, seed)
	if nil != err {
		b.Fatal("unexpected error in setting up")
	}

	b.ResetTimer()
	msg := make([]byte, lmots.N)
	rand.Reader.Read(msg)
	// what if no more leaf to use in the Merkle agent
	for i := 0; i < b.N; i++ {
		_, sig, err := Sign(merkleAgent, msg)
		if nil != err {
			if err.Error() == "Warning: this is the last signature" {
				b.Log("merkleAgent has been worn out, aborting...")
				break
			} else {
				b.Fatalf("error in signing %x: %s", msg, err)
			}
		}

		if !Verify(merkleAgent.Root, msg, sig) {
			b.Log(i)
			b.Fatal("verification failed")
		}
	}
}
