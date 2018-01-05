package lms

import (
	"bytes"
	"encoding/gob"
)

func (sig *MerkleSig) Serialize() ([]byte, error) {
	buf := new(bytes.Buffer)
	enc := gob.NewEncoder(buf)

	if err := enc.Encode(sig); nil != err {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (sig *MerkleSig) Deserialize(data []byte) error {
	buf := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buf)

	return dec.Decode(sig)
}
