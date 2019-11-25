package ecgroup

import (
	"fmt"
	"testing"
)

func TestGroupCurveEncodingP384(t *testing.T) {
	p384 := P384()
	_, err := curveEncoding(p384)
	if err != nil {
		t.Fatal(err)
	}
}

func TestGroupCurvePointSerializationP384(t *testing.T) {
	p384 := P384()
	P, err := curveEncoding(p384)
	if err != nil {
		t.Fatal(err)
	}

	checkSerialize(p384, P)
}

func TestGroupCurvePointSerializationWithCompressionP384(t *testing.T) {
	p384 := P384()
	P, err := curveEncoding(p384)
	if err != nil {
		t.Fatal(err)
	}

	P.compress = true
	checkSerialize(p384, P)
}

func TestGroupCurveEncodingP521(t *testing.T) {
	p521 := P521()
	_, err := curveEncoding(p521)
	if err != nil {
		t.Fatal(err)
	}
}

func TestGroupCurvePointSerializationP521(t *testing.T) {
	p521 := P521()
	P, err := curveEncoding(p521)
	if err != nil {
		t.Fatal(err)
	}

	checkSerialize(p521, P)
}

func TestGroupCurvePointSerializationWithCompressionP521(t *testing.T) {
	p521 := P521()
	P, err := curveEncoding(p521)
	if err != nil {
		t.Fatal(err)
	}

	P.compress = true
	checkSerialize(p521, P)
}

func curveEncoding(curve GroupCurve) (Point, error) {
	P, err := curve.EncodeToGroup([]byte("test"))
	if err != nil {
		return Point{}, err
	}

	if !P.IsValid(curve) {
		return Point{}, fmt.Errorf("Didn't generated valid curve point")
	}

	return P, nil
}

func checkSerialize(curve GroupCurve, P Point) error {
	buf := P.Serialize(curve)
	Q, err := Point{}.New().Deserialize(curve, buf)
	if err != nil {
		return err
	}

	if (P.compress && len(buf) != curve.consts.byteLength+1) ||
		len(buf) != (2*curve.consts.byteLength)+1 {
		return fmt.Errorf("Incorrect buffer length")
	}

	if Q.X.Cmp(P.X) != 0 {
		return fmt.Errorf("X coordinates are not equal, Q.X: %v, P.X: %v", Q.X, P.X)
	} else if Q.Y.Cmp(P.Y) != 0 {
		return fmt.Errorf("Y coordinates are not equal, Q.Y: %v, P.Y: %v", Q.Y, P.Y)
	}
	return nil
}
