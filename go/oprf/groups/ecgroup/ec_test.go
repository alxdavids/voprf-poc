package ecgroup

import (
	"crypto/elliptic"
	"crypto/sha512"
	"fmt"
	"testing"

	oc "github.com/alxdavids/oprf-poc/go/oprf/oprfCrypto"
	"github.com/cloudflare/circl/ecc/p384"
)

func TestGroupCurveEncodingP384(t *testing.T) {
	curve := CreateNistCurve(p384.P384(), sha512.New(), oc.HKDFExtExp{})
	_, err := curveEncoding(curve)
	if err != nil {
		t.Fatal(err)
	}
}

func TestGroupCurvePointSerializationP384(t *testing.T) {
	curve := CreateNistCurve(p384.P384(), sha512.New(), oc.HKDFExtExp{})
	P, err := curveEncoding(curve)
	if err != nil {
		t.Fatal(err)
	}

	checkSerialize(curve, P)
}

func TestGroupCurvePointSerializationWithCompressionP384(t *testing.T) {
	curve := CreateNistCurve(p384.P384(), sha512.New(), oc.HKDFExtExp{})
	P, err := curveEncoding(curve)
	if err != nil {
		t.Fatal(err)
	}

	P.compress = true
	checkSerialize(curve, P)
}

func TestGroupCurveEncodingP521(t *testing.T) {
	curve := CreateNistCurve(elliptic.P521(), sha512.New(), oc.HKDFExtExp{})
	_, err := curveEncoding(curve)
	if err != nil {
		t.Fatal(err)
	}
}

func TestGroupCurvePointSerializationP521(t *testing.T) {
	curve := CreateNistCurve(elliptic.P521(), sha512.New(), oc.HKDFExtExp{})
	P, err := curveEncoding(curve)
	if err != nil {
		t.Fatal(err)
	}

	checkSerialize(curve, P)
}

func TestGroupCurvePointSerializationWithCompressionP521(t *testing.T) {
	curve := CreateNistCurve(elliptic.P521(), sha512.New(), oc.HKDFExtExp{})
	P, err := curveEncoding(curve)
	if err != nil {
		t.Fatal(err)
	}

	P.compress = true
	checkSerialize(curve, P)
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

	if (P.compress && len(buf) != curve.ByteLength()+1) ||
		len(buf) != (2*curve.ByteLength())+1 {
		return fmt.Errorf("Incorrect buffer length")
	}

	if Q.X.Cmp(P.X) != 0 {
		return fmt.Errorf("X coordinates are not equal, Q.X: %v, P.X: %v", Q.X, P.X)
	} else if Q.Y.Cmp(P.Y) != 0 {
		return fmt.Errorf("Y coordinates are not equal, Q.Y: %v, P.Y: %v", Q.Y, P.Y)
	}
	return nil
}
