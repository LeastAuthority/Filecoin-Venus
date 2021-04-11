// +build gofuzz

package chaos

import (
	"bytes"
	"errors"
	"reflect"

	gofuzz "github.com/google/gofuzz"
	fleece "github.com/leastauthority/fleece/fuzzing"
)

func FuzzState_structured(data []byte) int {
	state1 := State{}
	f := gofuzz.NewFromGoFuzz(data).NilChance(.1).NumElements(1, 1000)
	f.Fuzz(&state1)

	writer1 := new(bytes.Buffer)
	if err := state1.MarshalCBOR(writer1); err != nil {
		return fleece.FuzzDiscard
	}

	state2 := State{}
	err := state2.UnmarshalCBOR(bytes.NewReader(writer1.Bytes()))
	if err != nil {
		panic(errors.New("unable to decode encoded state"))
	}

	writer2 := new(bytes.Buffer)
	if err := state2.MarshalCBOR(writer2); err != nil {
		panic(errors.New("unable to re-encode decoded state"))
	}

	if !reflect.DeepEqual(state1, state2) {
		panic(errors.New("decoded states don't match"))
	}
	return fleece.FuzzNormal
}

func FuzzState_raw(data []byte) int {
	state1 := State{}
	err := state1.UnmarshalCBOR(bytes.NewBuffer(data))
	if err != nil {
		return fleece.FuzzNormal
	}

	writer1 := new(bytes.Buffer)
	err = state1.MarshalCBOR(writer1)
	if err != nil {
		panic(errors.New("unable to encode decoded state"))
	}

	state2 := State{}
	err = state2.UnmarshalCBOR(writer1)
	if err != nil {
		panic(errors.New("unable to decode re-encoded state"))
	}

	if !reflect.DeepEqual(state1, state2) {
		panic(errors.New("decoded states don't match"))
	}

	return fleece.FuzzNormal
}
