package lms

import (
	"bytes"
	cryptorand "crypto/rand"
	"encoding/gob"

	"github.com/LoCCS/lmots"
	"github.com/LoCCS/lmots/rand"
)

// KeyIterator is a prkg to produce a key chain for
// user based on a seed
type KeyIterator struct {
	rng *rand.Rand
	// the 0-based index of next running prkgation
	//	w.r.t the initial genesis seed
	offset uint32
	// options specifying stuff like nonce for
	//	randomizing hash function
	*lmots.LMOpts
}

// NewKeyIterator makes a prkg
func NewKeyIterator(compactSeed []byte) *KeyIterator {
	prkg := new(KeyIterator)

	prkg.rng = rand.New(compactSeed)
	prkg.offset = 0
	prkg.LMOpts = lmots.NewLMOpts()
	// to be remove the LM-OTS library
	if _, err := cryptorand.Read(prkg.LMOpts.I[:]); nil != err {
		return nil
	}

	return prkg
}

// Next estimates and returns the next sk-pk pair
func (prkg *KeyIterator) Next() (*lmots.PrivateKey, error) {
	prkg.LMOpts.KeyIdx = prkg.offset
	keyPair, err := lmots.GenerateKey(prkg.LMOpts, prkg.rng)

	prkg.offset++

	return keyPair, err
}

// Offset returns 0-based index of the **next** key
// returned by this prkg
func (prkg *KeyIterator) Offset() uint32 {
	return prkg.offset
}

type keyItrEx struct {
	Seed   []byte
	Offset uint32
	Opts   *lmots.LMOpts
}

// GobEncode customizes the Gob encoding scheme for KeyIterator
func (prkg KeyIterator) GobEncode() ([]byte, error) {
	prkgEx := &keyItrEx{
		Seed:   prkg.rng.Seed(),
		Offset: prkg.offset,
		Opts:   prkg.LMOpts,
	}

	buf := new(bytes.Buffer)
	if err := gob.NewEncoder(buf).Encode(prkgEx); nil != err {
		return nil, err
	}

	return buf.Bytes(), nil
}

// GobDecode customizes the Gob decoding scheme for KeyIterator
func (prkg *KeyIterator) GobDecode(data []byte) error {
	prkgEx := new(keyItrEx)
	buf := bytes.NewBuffer(data)
	if err := gob.NewDecoder(buf).Decode(prkgEx); nil != err {
		return err
	}

	prkg.rng = rand.New(prkgEx.Seed)
	prkg.offset = prkgEx.Offset
	prkg.LMOpts = prkgEx.Opts

	return nil
}
