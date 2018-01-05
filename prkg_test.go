package lms

import (
	"bytes"
	"encoding/gob"
	"testing"

	"github.com/LoCCS/lmots"
	"github.com/LoCCS/lmots/rand"
)

func TestKeyIteratorGobEncoding(t *testing.T) {
	seed := make([]byte, lmots.N)
	rand.Reader.Read(seed)

	prkg := NewKeyIterator(seed)
	prkg.Next()

	buf := new(bytes.Buffer)
	if err := gob.NewEncoder(buf).Encode(prkg); nil != err {
		t.Fatal(err)
	}

	bs := buf.Bytes()

	prkg2 := new(KeyIterator)
	if err := gob.NewDecoder(buf).Decode(prkg2); nil != err {
		t.Fatal(err)
	}

	buf2 := new(bytes.Buffer)
	if err := gob.NewEncoder(buf2).Encode(prkg2); nil != err {
		t.Fatal(err)
	}
	if !bytes.Equal(bs, buf2.Bytes()) {
		t.Fatalf("invalid gob: want %x, got %x", bs, buf2.Bytes())
	}
}

// TestKeyIteratorExec tests correctness KeyIterator, including
// normal running (demo by iter) and recovered running from
// seed (demo by iter2)
func TestKeyIterator(t *testing.T) {
	seed := make([]byte, lmots.N)
	rand.Reader.Read(seed)

	iter := NewKeyIterator(seed)
	iter.Next()

	iter2 := new(KeyIterator)
	/*
		if !iter2.Init(iter.Serialize()) {
			t.Fatal("invalid integrated seed")
		}*/
	data, err := iter.Serialize()
	if nil != err {
		t.Fatal("unexpected error:", err)
	}
	if err := iter2.Deserialize(data); nil != err {
		t.Fatal("invalid integrated seed")
	}

	for i := 0; i < 2; i++ {
		sk1, _ := iter.Next()
		sk2, _ := iter2.Next()

		// check equality
		if !sk1.Equal(sk2) {
			t.Fatal("private keys should be equal")
		}
	}
}
