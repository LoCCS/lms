package lms

import (
	"bytes"
	"crypto/rand"
	mathrand "math/rand"
	"testing"

	"golang.org/x/crypto/sha3"

	"github.com/LoCCS/lmots"
	lmrand "github.com/LoCCS/lmots/rand"
	"github.com/LoCCS/lms/container/stack"
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

func mockUpPRKG() (*KeyIterator, error) {
	seed := make([]byte, lmots.N)
	if _, err := rand.Read(seed); nil != err {
		return nil, err
	}

	prkg := new(KeyIterator)
	prkg.rng = lmrand.New(seed)
	prkg.offset = mathrand.Uint32()
	prkg.LMOpts = lmots.NewLMOpts()

	if _, err := rand.Read(prkg.LMOpts.I[:]); nil != err {
		return nil, err
	}

	return prkg, nil
}

func mockUpTreeHashStack() (*TreeHashStack, error) {
	ths := new(TreeHashStack)

	ths.leaf = mathrand.Uint32() % 1024
	ths.leafUpper = ths.leaf + 256
	ths.height = mathrand.Uint32()%20 + 1

	ths.nodeStack = stack.New()
	ell := mathrand.Uint32() % 32
	for i := uint32(0); i < ell; i++ {
		node := &Node{
			Height: mathrand.Uint32(),
			Nu:     make([]byte, lmots.N),
			Index:  mathrand.Uint32(),
		}
		if _, err := rand.Read(node.Nu); nil != err {
			return nil, err
		}

		ths.nodeStack.Push(node)
	}

	return ths, nil
}

func isLMSigEqual(a, b *lmots.Sig) bool {
	if a == b {
		return true
	}

	if (nil == a) || (nil == b) {
		return false
	}

	if !bytes.Equal(a.Typecode[:], b.Typecode[:]) ||
		!bytes.Equal(a.C, b.C) {
		return false
	}

	if len(a.Sigma) != len(b.Sigma) {
		return false
	}

	for i := range a.Sigma {
		if !bytes.Equal(a.Sigma[i], b.Sigma[i]) {
			return false
		}
	}

	return true
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
		t.Fatalf("invalid Leaf: want %v, got %v", merkleSig.Leaf, merkleSig2.Leaf)
	}
	if !merkleSig.LeafPk.Equal(merkleSig2.LeafPk) {
		t.Fatal("invalid OTS pubkey")
	}
	if !isLMSigEqual(merkleSig.LMSig, merkleSig2.LMSig) {
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

func TestPRKGSerialization(t *testing.T) {
	prkg, err := mockUpPRKG()
	if nil != err {
		t.Fatal(err)
	}

	data, err := prkg.Serialize()
	if nil != err {
		t.Fatal(err)
	}

	prkg2 := new(KeyIterator)
	if err := prkg2.Deserialize(data); nil != err {
		t.Fatal(err)
	}

	data2, err := prkg2.Serialize()
	if nil != err {
		t.Fatal(err)
	}
	if !bytes.Equal(data, data2) {
		t.Fatalf("invalid bytes: want %x, got %x", data, data2)
	}
}

func TestTreeHashStackSerialization(t *testing.T) {
	ths, err := mockUpTreeHashStack()
	if nil != err {
		t.Fatal(err)
	}

	data, err := ths.Serialize()
	if nil != err {
		t.Fatal(err)
	}

	ths2 := new(TreeHashStack)
	if err := ths2.Deserialize(data); nil != err {
		t.Fatal(err)
	}

	data2, err := ths2.Serialize()
	if !bytes.Equal(data, data2) {
		t.Fatalf("invalid gob: want %x, got %x", data, data2)
	}
}
