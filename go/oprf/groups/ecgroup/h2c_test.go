package ecgroup

import (
	"errors"
	"testing"
)

var (
	testInputs = []([]byte){
		[]byte{},
		[]byte{1},
		[]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		[]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		[]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
	}
)

func TestHashToCurveP384(t *testing.T) {
	curve := P384()
	err := performHashToCurve(curve)
	if err != nil {
		t.Fatal(err)
	}
}

func TestHashToCurveP521(t *testing.T) {
	curve := P521()
	err := performHashToCurve(curve)
	if err != nil {
		t.Fatal(err)
	}
}

// performs hash to curve for each of the test inputs
func performHashToCurve(curve GroupCurve) error {
	params, err := getH2CParams(curve)
	if err != nil {
		return err
	}
	for _, alpha := range testInputs {
		R, err := params.hashToCurve(alpha)
		if err != nil {
			return err
		}
		// there are no test vectors so I guess we should just check whether the
		// point is valid for now
		if !R.IsValid(curve) {
			return errors.New("Failed to generate a valid point")
		}
	}
	return nil
}
