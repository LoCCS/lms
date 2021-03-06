package lms

import (
	"bytes"
	"encoding/gob"
)

// Serialize marshals a prkg into gob bytes
func (prkg *KeyIterator) Serialize() ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := gob.NewEncoder(buf).Encode(prkg); nil != err {
		return nil, err
	}

	return buf.Bytes(), nil
}

// Deserialize unmarshals the prkg from gob bytes
func (prkg *KeyIterator) Deserialize(data []byte) error {
	return gob.NewDecoder(bytes.NewBuffer(data)).Decode(prkg)
}

// Serialize marshals a MerkleSig into gob bytes
func (sig *MerkleSig) Serialize() ([]byte, error) {
	buf := new(bytes.Buffer)
	enc := gob.NewEncoder(buf)

	if err := enc.Encode(sig); nil != err {
		return nil, err
	}

	return buf.Bytes(), nil
}

// Deserialize unmarshals the MerkleSig from gob bytes
func (sig *MerkleSig) Deserialize(data []byte) error {
	buf := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buf)

	return dec.Decode(sig)
}

// Serialize marshals the TreeHashStack as Gob bytes
func (ths *TreeHashStack) Serialize() ([]byte, error) {
	buf := new(bytes.Buffer)

	if err := gob.NewEncoder(buf).Encode(ths); nil != err {
		return nil, err
	}

	return buf.Bytes(), nil
}

// Deserialize unmarshals the TreeHashStack from the Gob bytes
func (ths *TreeHashStack) Deserialize(data []byte) error {
	return gob.NewDecoder(bytes.NewBuffer(data)).Decode(ths)
}
