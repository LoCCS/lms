package lms

import (
	"bytes"
	"encoding/binary"

	"github.com/LoCCS/lmots"
	"github.com/LoCCS/lmots/rand"
)

// KeyIterator is a prkgator to produce a key chain for
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

// NewKeyIterator makes a key pair prkgator
func NewKeyIterator(compactSeed []byte) *KeyIterator {
	prkg := new(KeyIterator)

	prkg.rng = rand.New(compactSeed)
	prkg.offset = 0
	//prkg.LMOpts = new(lmots.LMOpts)
	prkg.LMOpts = lmots.NewLMOpts()

	return prkg
}

// Init initialises the prkg with the composite seed
// exported by Serialize()
func (prkg *KeyIterator) Init(compositeSeed []byte) bool {
	buf := bytes.NewBuffer(compositeSeed)

	var fieldLen uint8
	// 1. len(seed)
	if err := binary.Read(buf, binary.BigEndian,
		&fieldLen); (nil != err) && (0 == fieldLen) {
		return false
	}
	// 2. compactSeed
	compactSeed := make([]byte, fieldLen)
	if err := binary.Read(buf, binary.BigEndian,
		compactSeed); nil != err {
		return false
	}
	// initialise rng
	prkg.rng = rand.New(compactSeed)

	// 3. offset
	var offset uint32
	if err := binary.Read(buf, binary.BigEndian,
		&offset); nil != err {
		return false
	}
	// feed offset to LMOpts
	prkg.offset = offset

	// initialise LMOpts if needed before going on
	if nil == prkg.LMOpts {
		prkg.LMOpts = new(lmots.LMOpts)
	}
	return prkg.LMOpts.Deserialize(buf.Bytes())
}

// Next estimates and returns the next sk-pk pair
func (prkg *KeyIterator) Next() (*lmots.PrivateKey, error) {
	prkg.LMOpts.SetKeyIdx(prkg.offset)
	keyPair, err := lmots.GenerateKey(prkg.LMOpts, prkg.rng)

	prkg.offset++

	return keyPair, err
}

// Offset returns 0-based index of the **next** running prkgation
func (prkg *KeyIterator) Offset() uint32 {
	return prkg.offset
}

// Serialize encodes the key iterator as
// +---------------------------------------------+
// |	len(seed)||seed||offset||len(nonce)||nonce	|
// +---------------------------------------------+
// the byte slice export from here makes up
// everything needed to recovered the state the prkg
// So unless it's your first-time use, you should
// store this byte slice so as to snapshot the prkg
func (prkg *KeyIterator) Serialize() []byte {
	buf := new(bytes.Buffer)

	seed := prkg.rng.Seed()
	// len(seed)
	binary.Write(buf, binary.BigEndian, uint8(len(seed)))
	// seed
	binary.Write(buf, binary.BigEndian, seed)

	// offset
	binary.Write(buf, binary.BigEndian, prkg.offset)

	// LMOpts
	binary.Write(buf, binary.BigEndian, prkg.LMOpts.Serialize())

	return buf.Bytes()
}
