package ecgroup

import (
	"crypto/sha512"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/alxdavids/voprf-poc/go/oerr"
	gg "github.com/alxdavids/voprf-poc/go/oprf/groups"
	"github.com/alxdavids/voprf-poc/go/oprf/utils/constants"
	"github.com/stretchr/testify/assert"
)

var (
	testCiphersuites = []int{
		//gg.OPRF_CURVE25519_SHA512,
		gg.OPRF_CURVE448_SHA512,
		//gg.OPRF_P256_SHA512,
		gg.OPRF_P384_SHA512,
		gg.OPRF_P521_SHA512,
	}
)

func TestCiphersuiteFromID(t *testing.T) {
	for _, c := range testCiphersuites {
		ciphersuiteFromID(t, c)
	}
}

func TestCiphersuiteFromIDInvalid(t *testing.T) {
	ciphersuiteFromIDInvalid(t, gg.OPRF_INVALID_CIPHERSUITE)
}

func TestGroupCurveEncodingP384(t *testing.T) {
	curve := initCurve(t, gg.GROUP_P384)
	_, err := curveEncoding(curve)
	if err != nil {
		t.Fatal(err)
	}
}

func TestGroupCurvePointSerializationP384(t *testing.T) {
	curve := initCurve(t, gg.GROUP_P384)
	P, err := curveEncoding(curve)
	if err != nil {
		t.Fatal(err)
	}

	err = checkSerialize(curve, P)
	if err != nil {
		t.Fatal(err)
	}
}

func TestGroupCurvePointSerializationWithCompressionP384(t *testing.T) {
	curve := initCurve(t, gg.GROUP_P384)
	P, err := curveEncoding(curve)
	if err != nil {
		t.Fatal(err)
	}

	P.compress = true
	err = checkSerialize(curve, P)
	if err != nil {
		t.Fatal(err)
	}
}

func TestGroupCurveEncodingP521(t *testing.T) {
	curve := initCurve(t, gg.GROUP_P521)
	_, err := curveEncoding(curve)
	if err != nil {
		t.Fatal(err)
	}
}

func TestGroupCurvePointSerializationP521(t *testing.T) {
	curve := initCurve(t, gg.GROUP_P521)
	P, err := curveEncoding(curve)
	if err != nil {
		t.Fatal(err)
	}

	err = checkSerialize(curve, P)
	if err != nil {
		t.Fatal(err)
	}
}

func TestGroupCurvePointSerializationWithCompressionP521(t *testing.T) {
	curve := initCurve(t, gg.GROUP_P521)
	P, err := curveEncoding(curve)
	if err != nil {
		t.Fatal(err)
	}

	P.compress = true
	err = checkSerialize(curve, P)
	if err != nil {
		t.Fatal(err)
	}
}

func TestGroupCurvePointSerializationC448(t *testing.T) {
	curve := initCurve(t, gg.GROUP_CURVE448)
	P, err := curveEncoding(curve)
	if err != nil {
		t.Fatal(err)
	}

	err = checkSerialize(curve, P)
	if err != nil {
		t.Fatal(err)
	}
}

func TestGroupCurvePointSerializationWithCompressionC448(t *testing.T) {
	curve := initCurve(t, gg.GROUP_CURVE448)
	P, err := curveEncoding(curve)
	if err != nil {
		t.Fatal(err)
	}

	P.compress = true
	err = checkSerialize(curve, P)
	if err != nil {
		t.Fatal(err)
	}
}

func TestPointAdditionP384(t *testing.T) {
	checkPointAddition(t, gg.GROUP_P384)
}

func TestPointAdditionP521(t *testing.T) {
	checkPointAddition(t, gg.GROUP_P521)
}

func TestPointEqualityP384(t *testing.T) {
	checkPointEquality(t, gg.GROUP_P384)
}

func TestPointEqualityP521(t *testing.T) {
	checkPointEquality(t, gg.GROUP_P521)
}

func TestPointEqualityFailsOnBadGroups(t *testing.T) {
	p384 := initCurve(t, gg.GROUP_P384)
	P, err := curveEncoding(p384)
	if err != nil {
		t.Fatal(err)
	}

	p521 := initCurve(t, gg.GROUP_P521)
	Q, err := curveEncoding(p521)
	if err != nil {
		t.Fatal(err)
	}
	assert.False(t, P.Equal(Q))
}

func TestPointEqualityFailsOnInvalidCallerPoint(t *testing.T) {
	p384 := initCurve(t, gg.GROUP_P384)
	P, err := curveEncoding(p384)
	if err != nil {
		t.Fatal(err)
	}
	P.X = constants.MinusOne

	p521 := initCurve(t, gg.GROUP_P521)
	Q, err := curveEncoding(p521)
	if err != nil {
		t.Fatal(err)
	}
	assert.False(t, P.Equal(Q))
}

func TestPointEqualityFailsOnInvalidInputPoint(t *testing.T) {
	p384 := initCurve(t, gg.GROUP_P384)
	P, err := curveEncoding(p384)
	if err != nil {
		t.Fatal(err)
	}

	p521 := initCurve(t, gg.GROUP_P521)
	Q, err := curveEncoding(p521)
	if err != nil {
		t.Fatal(err)
	}
	Q.X = constants.MinusOne
	assert.False(t, P.Equal(Q))
}

func checkPointAddition(t *testing.T, curveID int) {
	curve := initCurve(t, curveID)
	P, err := curveEncoding(curve)
	if err != nil {
		t.Fatal(err)
	}
	P1, err := curveEncoding(curve)
	if err != nil {
		t.Fatal(err)
	}
	P2, err := curveEncoding(curve)
	if err != nil {
		t.Fatal(err)
	}
	x, err := curve.RandomScalar()
	if err != nil {
		t.Fatal(err)
	}
	y, err := curve.RandomScalar()
	if err != nil {
		t.Fatal(err)
	}
	xP1, err := P1.ScalarMult(x)
	if err != nil {
		t.Fatal(err)
	}
	yP2, err := P2.ScalarMult(y)
	if err != nil {
		t.Fatal(err)
	}
	xP1yP2, err := xP1.Add(yP2)
	if err != nil {
		t.Fatal(err)
	}
	xyP, err := P.ScalarMult(new(big.Int).Add(x, y))
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, xyP.Equal(xP1yP2))
}

func checkPointEquality(t *testing.T, curveID int) {
	curve := initCurve(t, curveID)
	P, err := curveEncoding(curve)
	if err != nil {
		t.Fatal(err)
	}
	Q := P
	assert.True(t, P.Equal(Q))
}

func ciphersuiteFromID(t *testing.T, id int) {
	ciph, err := gg.Ciphersuite{}.FromID(id, GroupCurve{})
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, ciph.ID(), id)
	assert.Equal(t, ciph.Hash(), sha512.New())
}

func ciphersuiteFromIDInvalid(t *testing.T, id int) {
	_, err := gg.Ciphersuite{}.FromID(id, GroupCurve{})
	if !errors.Is(err, oerr.ErrUnsupportedCiphersuite) {
		t.Fatal("Error didn't occur")
	}
}
func curveEncoding(curve GroupCurve) (Point, error) {
	P, err := curve.HashToGroup([]byte("test"))
	if err != nil {
		return Point{}, err
	}

	if !P.IsValid() {
		return Point{}, errors.New("didn't generate valid curve point")
	}

	ret, err := castToPoint(P)
	if err != nil {
		return Point{}, err
	}

	return ret, nil
}

func checkSerialize(curve GroupCurve, P Point) error {
	buf, err := P.Serialize()
	if err != nil {
		return err
	}

	Q, err := Point{}.New(curve).Deserialize(buf)
	if err != nil {
		return err
	}

	if (P.compress && len(buf) != curve.ByteLength()+1) ||
		(!P.compress && len(buf) != (2*curve.ByteLength())+1) {
		if P.compress {
			return fmt.Errorf("Incorrect buffer length: expected %v got %v", curve.ByteLength()+1, len(buf))
		}
		return fmt.Errorf("Incorrect buffer length: expected %v, got %v", (2*curve.ByteLength())+1, len(buf))
	}

	qPoint, err := castToPoint(Q)
	if err != nil {
		return err
	}
	if !qPoint.Equal(P) {
		return errors.New("qPoint and P are not equal points")
	}
	return nil
}

func initCurve(t *testing.T, curveID int) GroupCurve {
	g, err := GroupCurve{}.New(curveID)
	if err != nil {
		t.Fatal(err)
	}
	curve, err := castToCurve(g)
	if err != nil {
		t.Fatal(err)
	}
	return curve
}
