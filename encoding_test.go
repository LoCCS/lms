package lms

import (
	"bytes"
	"crypto/rand"
	"encoding/gob"
	mathrand "math/rand"
	"testing"

	"golang.org/x/crypto/sha3"

	"github.com/LoCCS/lmots"
)

func mockUpMerkleSig() (*MerkleSig, error) {
	// make a dummy pubkey and OTS sig
	hash := sha3.Sum256([]byte("Hello LMS"))

	dummyOpts := lmots.NewLMOpts()
	sk, err := lmots.GenerateKey(dummyOpts, rand.Reader)
	if nil != err {
		return nil, err
	}

	sig, err := lmots.Sign(rand.Reader, sk, hash[:])
	if nil != err {
		return nil, err
	}

	const H = 16
	merkleSig := &MerkleSig{
		Leaf:   mathrand.Uint32(),
		LeafPk: &sk.PublicKey,
		LMSig:  sig,
	}

	merkleSig.Auth = make([][]byte, H)
	for i := range merkleSig.Auth {
		merkleSig.Auth[i] = make([]byte, 3)
		if _, err := rand.Read(merkleSig.Auth[i]); nil != err {
			return nil, err
		}
	}

	return merkleSig, nil
}

func TestMerkleSigEncoding(t *testing.T) {
	merkleSig, err := mockUpMerkleSig()
	if nil != err {
		t.Fatal(err)
	}
	// marshall the sig into a byte sequence
	buf := new(bytes.Buffer)
	enc := gob.NewEncoder(buf)
	if err := enc.Encode(&merkleSig); nil != err {
		t.Fatal(err)
	}

	// unmarshall the byte sequence into a sig
	dec := gob.NewDecoder(buf)
	merkleSig2 := new(MerkleSig)
	if err := dec.Decode(merkleSig2); nil != err {
		t.Fatal(err)
	}
}

func TestMerkleSigSerialization(t *testing.T) {
	merkleSig, err := mockUpMerkleSig()
	if nil != err {
		t.Fatal(err)
	}

	data, err := merkleSig.Serialize()
	if nil != err {
		t.Fatal(err)
	}

	merkleSig2 := new(MerkleSig)
	if err := merkleSig2.Deserialize(data); nil != err {
		t.Fatal(err)
	}

	if merkleSig.Leaf != merkleSig2.Leaf {
		t.Fatalf("invalid Leaf: want %v, got %v", merkleSig.Leaf != merkleSig2.Leaf)
	}
	if !merkleSig.LeafPk.Equal(merkleSig.LeafPk) {
		t.Fatal("invalid OTS pubkey")
	}
	if !merkleSig.LMSig.Equal(merkleSig.LMSig) {
		t.Fatal("invalid OTS signature")
	}
	if len(merkleSig.Auth) != len(merkleSig2.Auth) {
		t.Fatalf("invalid len(Auth): want %v, got %v",
			len(merkleSig.Auth), len(merkleSig2.Auth))
	}
	for i := range merkleSig.Auth {
		if !bytes.Equal(merkleSig.Auth[i], merkleSig2.Auth[i]) {
			t.Fatalf("invalid Auth[%v]: want %x, got %x", i,
				merkleSig.Auth[i], merkleSig2.Auth[i])
		}
	}

	//t.Logf("%+v\n", merkleSig)
	//t.Logf("%+v\n", merkleSig2)
}
