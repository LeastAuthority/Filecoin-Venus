// +build gofuzz

package types

import (
	"bytes"
	"errors"

	fleece "github.com/leastauthority/fleece/fuzzing"
)

func FuzzSignedMessage_raw(data []byte) int {
	signedMsg1 := SignedMessage{}
	err := signedMsg1.UnmarshalCBOR(bytes.NewReader(data))
	if err != nil {
		return fleece.FuzzNormal
	}

	writer1 := new(bytes.Buffer)
	if err := signedMsg1.MarshalCBOR(writer1); err != nil {
		panic(errors.New("unable to encode decoded signed message"))
	}

	signedMsg2 := SignedMessage{}
	if err := signedMsg2.UnmarshalCBOR(writer1); err != nil {
		panic(errors.New("unable to decode re-encoded signed message"))
	}

	return fleece.FuzzNormal
}