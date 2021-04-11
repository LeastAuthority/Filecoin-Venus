// +build gofuzz

package crypto

import (
	"bytes"
	"errors"
	fleece "github.com/leastauthority/fleece/fuzzing"
)

func FuzzKeyInfo_raw(data []byte) int {
	keyInfo1 := KeyInfo{}
	err := keyInfo1.UnmarshalCBOR(bytes.NewReader(data))
	if err != nil {
		return fleece.FuzzNormal
	}

	writer1 := new(bytes.Buffer)
	if err := keyInfo1.MarshalCBOR(writer1); err != nil {
		panic(errors.New("unable to encode decoded input"))
	}

	keyInfo2 := KeyInfo{}
	if err := keyInfo2.UnmarshalCBOR(writer1); err != nil {
		panic(errors.New("unable to decode re-encoded input"))
	}

	return fleece.FuzzNormal
}