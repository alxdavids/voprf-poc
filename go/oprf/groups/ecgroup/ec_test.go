package ecgroup

import (
	"crypto/elliptic"
	"crypto/sha512"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/alxdavids/oprf-poc/go/oerr"
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
	if err.Err() != nil {
		t.Fatal(err)
	}
}

func TestGroupCurvePointSerializationP384(t *testing.T) {
	curve := CreateNistCurve(p384.P384(), sha512.New(), oc.HKDFExtExp{})
	P, err := curveEncoding(curve)
	if err.Err() != nil {
		t.Fatal(err)
	}

	checkSerialize(curve, P)
}

func TestGroupCurvePointSerializationWithCompressionP384(t *testing.T) {
	curve := CreateNistCurve(p384.P384(), sha512.New(), oc.HKDFExtExp{})
	P, err := curveEncoding(curve)
	if err.Err() != nil {
		t.Fatal(err)
	}

	P.compress = true
	checkSerialize(curve, P)
}

func TestGroupCurveEncodingP521(t *testing.T) {
	curve := CreateNistCurve(elliptic.P521(), sha512.New(), oc.HKDFExtExp{})
	_, err := curveEncoding(curve)
	if err.Err() != nil {
		t.Fatal(err)
	}
}

func TestGroupCurvePointSerializationP521(t *testing.T) {
	curve := CreateNistCurve(elliptic.P521(), sha512.New(), oc.HKDFExtExp{})
	P, err := curveEncoding(curve)
	if err.Err() != nil {
		t.Fatal(err)
	}

	checkSerialize(curve, P)
}

func TestGroupCurvePointSerializationWithCompressionP521(t *testing.T) {
	curve := CreateNistCurve(elliptic.P521(), sha512.New(), oc.HKDFExtExp{})
	P, err := curveEncoding(curve)
	if err.Err() != nil {
		t.Fatal(err)
	}

	P.compress = true
	checkSerialize(curve, P)
}

func TestPointEqualityP384(t *testing.T) {
	checkPointEquality(t, p384.P384())
}

func TestPointEqualityP521(t *testing.T) {
	checkPointEquality(t, elliptic.P521())
}

func TestPointEqualityFailsOnBadGroups(t *testing.T) {
	p384 := CreateNistCurve(p384.P384(), sha512.New(), oc.HKDFExtExp{})
	P, err := curveEncoding(p384)
	if err.Err() != nil {
		t.Fatal(err)
	}
	p521 := CreateNistCurve(elliptic.P521(), sha512.New(), oc.HKDFExtExp{})
	Q, err := curveEncoding(p521)
	if err.Err() != nil {
		t.Fatal(err)
	}
	assert.False(t, P.Equal(Q))
}

func TestPointEqualityFailsOnInvalidCallerPoint(t *testing.T) {
	p384 := CreateNistCurve(p384.P384(), sha512.New(), oc.HKDFExtExp{})
	P, err := curveEncoding(p384)
	if err.Err() != nil {
		t.Fatal(err)
	}
	P.X = minusOne
	p521 := CreateNistCurve(elliptic.P521(), sha512.New(), oc.HKDFExtExp{})
	Q, err := curveEncoding(p521)
	if err.Err() != nil {
		t.Fatal(err)
	}
	assert.False(t, P.Equal(Q))
}

func TestPointEqualityFailsOnInvalidInputPoint(t *testing.T) {
	p384 := CreateNistCurve(p384.P384(), sha512.New(), oc.HKDFExtExp{})
	P, err := curveEncoding(p384)
	if err.Err() != nil {
		t.Fatal(err)
	}
	p521 := CreateNistCurve(elliptic.P521(), sha512.New(), oc.HKDFExtExp{})
	Q, err := curveEncoding(p521)
	if err.Err() != nil {
		t.Fatal(err)
	}
	Q.X = minusOne
	assert.False(t, P.Equal(Q))
}

func checkPointEquality(t *testing.T, curve elliptic.Curve) {
	nistCurve := CreateNistCurve(curve, sha512.New(), oc.HKDFExtExp{})
	P, err := curveEncoding(nistCurve)
	if err.Err() != nil {
		t.Fatal(err)
	}
	Q := P
	assert.True(t, P.Equal(Q))
}

func ciphersuiteFromString(t *testing.T, groupName string, verifiable bool) {
	s := ""
	if verifiable {
		s = "V"
	}
	ciphName := fmt.Sprintf("%sOPRF-%s-HKDF-SHA512-SSWU-RO", s, strings.ReplaceAll(groupName, "-", ""))
	ciph, err := gg.Ciphersuite{}.FromString(ciphName, GroupCurve{})
	if err.Err() != nil {
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
	if err != oerr.ErrUnsupportedH2C {
		t.Fatal("Error didn't occur")
	}
}

func ciphersuiteFromStringInvalidHash(t *testing.T, groupName string) {
	ciphName := fmt.Sprintf("OPRF-%s-HKDF-SHA256-SSWU-RO", strings.ReplaceAll(groupName, "-", ""))
	_, err := gg.Ciphersuite{}.FromString(ciphName, GroupCurve{})
	if err != oerr.ErrUnsupportedHash {
		t.Fatal("Error didn't occur")
	}
}

func ciphersuiteFromStringInvalidGroup(t *testing.T, groupName string) {
	ciphName := fmt.Sprintf("OPRF-%s-HKDF-SHA512-SSWU-RO", strings.ReplaceAll(groupName, "-", ""))
	_, err := gg.Ciphersuite{}.FromString(ciphName, GroupCurve{})
	if err != oerr.ErrUnsupportedGroup {
		t.Fatal("Error didn't occur")
	}
}

func curveEncoding(curve GroupCurve) (Point, oerr.Error) {
	P, err := curve.EncodeToGroup([]byte("test"))
	if err.Err() != nil {
		return Point{}, err
	}

	if !P.IsValid() {
		return Point{}, oerr.New("Didn't generated valid curve point", -1)
	}

	ret, err := castToPoint(P)
	if err.Err() != nil {
		return Point{}, err
	}

	return ret, oerr.Nil()
}

func checkSerialize(curve GroupCurve, P Point) oerr.Error {
	buf, err := P.Serialize()
	if err.Err() != nil {
		return err
	}
	Q, err := Point{}.New(curve).Deserialize(buf)
	if err.Err() != nil {
		return err
	}

	if (P.compress && len(buf) != curve.ByteLength()+1) ||
		len(buf) != (2*curve.ByteLength())+1 {
		return oerr.New("Incorrect buffer length", -1)
	}

	qPoint, err := castToPoint(Q)
	if err.Err() != nil {
		return err
	}
	if qPoint.Equal(P) {
		return oerr.New("qPoint and P are not equal points", -1)
	}
	return oerr.Nil()
}
