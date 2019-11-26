package ecgroup

import (
	"crypto/elliptic"
	"crypto/sha512"
	"fmt"
	"reflect"
	"strings"
	"testing"

	gg "github.com/alxdavids/oprf-poc/go/oprf/groups"
	oc "github.com/alxdavids/oprf-poc/go/oprf/oprfCrypto"
	"github.com/cloudflare/circl/ecc/p384"
	"github.com/stretchr/testify/assert"
)

var (
	testCurves = []string{"P-384", "P-521"}
)

func TestCiphersuiteFromString(t *testing.T) {
	for _, b := range []bool{false, true} {
		for _, c := range testCurves {
			ciphersuiteFromString(t, c, b)
		}
	}
}

func TestCiphersuiteFromStringInvalidH2C(t *testing.T) {
	for _, c := range testCurves {
		ciphersuiteFromStringInvalidH2C(t, c)
	}
}

func TestCiphersuiteFromStringInvalidHash(t *testing.T) {
	for _, c := range testCurves {
		ciphersuiteFromStringInvalidHash(t, c)
	}
}

func TestCiphersuiteFromStringInvalidGroup(t *testing.T) {
	ciphersuiteFromStringInvalidGroup(t, "P-256")
}

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

func ciphersuiteFromString(t *testing.T, groupName string, verifiable bool) {
	s := ""
	if verifiable {
		s = "V"
	}
	ciphName := fmt.Sprintf("%sOPRF-%s-HKDF-SHA512-SSWU-RO", s, strings.ReplaceAll(groupName, "-", ""))
	ciph, err := gg.Ciphersuite{}.FromString(ciphName, GroupCurve{})
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, ciph.Name(), ciphName)
	assert.Equal(t, ciph.H3(), sha512.New())
	assert.Equal(t, ciph.H4(), sha512.New())
	assert.Equal(t, ciph.POG().Name(), groupName)
	assert.Equal(t, ciph.Verifiable(), verifiable)
	if verifiable {
		assert.Equal(t, reflect.TypeOf(ciph.H5()).Name(), "HKDFExtExp")
	} else {
		assert.Equal(t, ciph.H5(), nil)
	}
}

func ciphersuiteFromStringInvalidH2C(t *testing.T, groupName string) {
	ciphName := fmt.Sprintf("OPRF-%s-HKDF-SHA512-ELL2", strings.ReplaceAll(groupName, "-", ""))
	_, err := gg.Ciphersuite{}.FromString(ciphName, GroupCurve{})
	if err != gg.ErrUnsupportedH2C {
		t.Fatal("Error didn't occur")
	}
}

func ciphersuiteFromStringInvalidHash(t *testing.T, groupName string) {
	ciphName := fmt.Sprintf("OPRF-%s-HKDF-SHA256-SSWU-RO", strings.ReplaceAll(groupName, "-", ""))
	_, err := gg.Ciphersuite{}.FromString(ciphName, GroupCurve{})
	if err != gg.ErrUnsupportedHash {
		t.Fatal("Error didn't occur")
	}
}

func ciphersuiteFromStringInvalidGroup(t *testing.T, groupName string) {
	ciphName := fmt.Sprintf("OPRF-%s-HKDF-SHA512-SSWU-RO", strings.ReplaceAll(groupName, "-", ""))
	_, err := gg.Ciphersuite{}.FromString(ciphName, GroupCurve{})
	if err != gg.ErrUnsupportedGroup {
		t.Fatal("Error didn't occur")
	}
}

func curveEncoding(curve GroupCurve) (Point, error) {
	P, err := curve.EncodeToGroup([]byte("test"))
	if err != nil {
		return Point{}, err
	}

	if !P.IsValid(curve) {
		return Point{}, fmt.Errorf("Didn't generated valid curve point")
	}

	ret, err := castToPoint(P)
	if err != nil {
		return Point{}, err
	}

	return ret, nil
}

func checkSerialize(curve GroupCurve, P Point) error {
	buf, err := P.Serialize(curve)
	if err != nil {
		return err
	}
	Q, err := Point{}.New().Deserialize(curve, buf)
	if err != nil {
		return err
	}

	if (P.compress && len(buf) != curve.ByteLength()+1) ||
		len(buf) != (2*curve.ByteLength())+1 {
		return fmt.Errorf("Incorrect buffer length")
	}

	qPoint, err := castToPoint(Q)
	if err != nil {
		return err
	}
	if qPoint.X.Cmp(P.X) != 0 {
		return fmt.Errorf("X coordinates are not equal, Q.X: %v, P.X: %v", qPoint.X, P.X)
	} else if qPoint.Y.Cmp(P.Y) != 0 {
		return fmt.Errorf("Y coordinates are not equal, Q.Y: %v, P.Y: %v", qPoint.Y, P.Y)
	}
	return nil
}
