// +build gofuzz

package exchange

import (
	"bytes"
	"errors"
	"reflect"

	gofuzz "github.com/google/gofuzz"
	fleece "github.com/leastauthority/fleece/fuzzing"
)

func FuzzBSTipset_structured(data []byte) int {
	ts1 := BSTipSet{}
	// NB: SIGABRT with empty input
	f := gofuzz.NewFromGoFuzz(data).NilChance(0).NumElements(1, 1000)
	f.Fuzz(&ts1)

	writer1 := new(bytes.Buffer)
	if err := ts1.MarshalCBOR(writer1); err != nil {
		return fleece.FuzzDiscard
	}

	ts2 := BSTipSet{}
	err := ts2.UnmarshalCBOR(bytes.NewReader(writer1.Bytes()))
	if err != nil {
		panic(errors.New("unable to decode encoded tipset"))
	}

	writer2 := new(bytes.Buffer)
	if err := ts2.MarshalCBOR(writer2); err != nil {
		panic(errors.New("unable to re-encode decoded state"))
	}

	if !reflect.DeepEqual(ts2, ts2) {
		panic(errors.New("decoded tipsets don't match"))
	}
	return fleece.FuzzNormal
}

func FuzzBSTipset_raw(data []byte) int {
	ts1 := BSTipSet{}
	err := ts1.UnmarshalCBOR(bytes.NewReader(data))
	if err != nil {
		return fleece.FuzzNormal
	}

	writer1 := new(bytes.Buffer)
	err = ts1.MarshalCBOR(writer1)
	if err != nil {
		panic(errors.New("unable to encode decoded state"))
	}

	ts2 := BSTipSet{}
	err = ts2.UnmarshalCBOR(writer1)
	if err != nil {
		panic(errors.New("unable to decode re-encoded state"))
	}

	if !reflect.DeepEqual(ts1, ts2) {
		panic(errors.New("decoded states don't match"))
	}

	return fleece.FuzzNormal
}

func FuzzRequest_structured(data []byte) int {
	request1 := Request{}
	f := gofuzz.NewFromGoFuzz(data).NilChance(.1).NumElements(1, 1000)
	f.Fuzz(&request1)

	err := request1.UnmarshalCBOR(bytes.NewReader(data))
	if err != nil {
		panic(err)
	}

	return fleece.FuzzNormal
}

func FuzzRequest_raw(data []byte) int {
	request1 := Request{}
	err := request1.UnmarshalCBOR(bytes.NewReader(data))
	if err != nil {
		return fleece.FuzzNormal
	}

	writer1 := new(bytes.Buffer)
	err = request1.MarshalCBOR(writer1)
	if err != nil {
		panic(errors.New("unable to encode decoded state"))
	}

	request2 := Request{}
	err = request2.UnmarshalCBOR(writer1)
	if err != nil {
		panic(errors.New("unable to decode re-encoded state"))
	}

	if !reflect.DeepEqual(request1, request2) {
		panic(errors.New("decoded states don't match"))
	}

	return fleece.FuzzNormal
}
