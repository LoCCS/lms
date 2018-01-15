package lms

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/LoCCS/lmots"
)

func TestMerkleAgent(t *testing.T) {
	const H = 8

	seed := make([]byte, lmots.N)
	if _, err := rand.Read(seed); nil != err {
		t.Fatal(err)
	}

	merkleAgent, err := NewMerkleAgent(H, seed)
	if nil != err {
		t.Fatal("error in making MerkleAgent:", err)
	}

	// make a random message
	msg := make([]byte, lmots.N)
	if _, err := rand.Read(msg); nil != err {
		t.Fatal(err)
	}

	var randRounds [1]uint8
	if _, err := rand.Read(randRounds[:]); nil != err {
		t.Fatal(err)
	}
	for randRounds[0] > 0 {
		Sign(merkleAgent, msg)

		randRounds[0]--
	}

	maData, err := merkleAgent.Serialize()
	if nil != err {
		t.Fatal(err)
	}

	prkgData := merkleAgent.SerializeSecretKey()

	merkleAgent2 := new(MerkleAgent)
	if err := merkleAgent2.RebuildMerkleAgent(maData, prkgData); nil != err {
		t.Fatal(err)
	}

	if maData2, err := merkleAgent2.Serialize(); nil != err {
		t.Fatal(err)
	} else if !bytes.Equal(maData, maData2) {
		t.Fatalf("invalid public components: want %x, got %x", maData, maData2)
	}

	prkgData2 := merkleAgent2.SerializeSecretKey()
	if !bytes.Equal(prkgData, prkgData2) {
		t.Fatalf("invalid private components: want %x, got %x", prkgData, prkgData2)
	}
}
