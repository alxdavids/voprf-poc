package ecgroup

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"hash"
	"io"
	"math/big"

	"github.com/alxdavids/oprf-poc/go/oerr"
	gg "github.com/alxdavids/oprf-poc/go/oprf/groups"
	"github.com/alxdavids/oprf-poc/go/oprf/utils"
	"github.com/alxdavids/oprf-poc/go/oprf/utils/constants"
	"github.com/cloudflare/circl/ecc/p384"
)

// GroupCurve implements the PrimeOrderGroup interface using an elliptic curve
// to provide the underlying group structure. The abstraction of the curve
// interface is based on the one used in draft-irtf-hash-to-curve-05.
type GroupCurve struct {
	ops        elliptic.Curve
	name       string
	hash       hash.Hash
	ee         utils.ExtractorExpander
	byteLength int
	nist       bool
	sgn0       func(*big.Int) *big.Int
	consts     CurveConstants
}

// New constructs a new GroupCurve object implementing the PrimeOrderGroup
// interface. Currently, the only supported curves are NIST P384 and P521.
func (c GroupCurve) New(name string) (gg.PrimeOrderGroup, error) {
	var curve elliptic.Curve
	var h hash.Hash
	var ee utils.ExtractorExpander
	switch name {
	case "P-384":
		curve = p384.P384()
		h = sha512.New()
		ee = utils.HKDFExtExp{}
		break
	case "P-521":
		curve = elliptic.P521()
		h = sha512.New()
		ee = utils.HKDFExtExp{}
		break
	default:
		return nil, oerr.ErrUnsupportedGroup
	}
	p := curve.Params().P
	isSqExp := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Sub(p, constants.One), new(big.Int).ModInverse(constants.Two, p)), p)
	sqrtExp := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Add(p, constants.One), new(big.Int).ModInverse(constants.Four, p)), p)
	return GroupCurve{
		ops:        curve,
		name:       name,
		hash:       h,
		ee:         ee,
		byteLength: (curve.Params().BitSize + 7) / 8,
		nist:       true,
		sgn0:       utils.Sgn0LE,
		consts: CurveConstants{
			a:       constants.MinusThree,
			sqrtExp: sqrtExp,
			isSqExp: isSqExp,
		},
	}, nil
}

// Order returns the order of the base point for the elliptic curve that is used
func (c GroupCurve) Order() *big.Int {
	return c.ops.Params().N
}

// P returns the order of the underlying field for the elliptic curve that is
// used
func (c GroupCurve) P() *big.Int {
	return c.ops.Params().P
}

// Generator returns a point in the curve representing a fixed generator  of the
// prime-order group.
func (c GroupCurve) Generator() gg.GroupElement {
	G := Point{}.New(c).(Point)
	G.X = c.ops.Params().Gx
	G.Y = c.ops.Params().Gy
	return G
}

// GeneratorMult returns k*G, where G is the generator of the curve.
func (c GroupCurve) GeneratorMult(k *big.Int) (gg.GroupElement, error) {
	G := c.Generator()
	return G.ScalarMult(k)
}

// ByteLength returns the length, in bytes, of a valid representation of a group
// element.
func (c GroupCurve) ByteLength() int {
	return c.byteLength
}

// EncodeToGroup invokes the hash_to_curve method for encoding bytes as curve
// points. The hash-to-curve method for the curve is implemented using the
// specification defined in draft-irtf-hash-to-curve-05.
func (c GroupCurve) EncodeToGroup(buf []byte) (gg.GroupElement, error) {
	params, err := getH2CParams(c)
	if err != nil {
		return nil, err
	}
	p, err := params.hashToCurve(buf)
	if err != nil {
		return nil, err
	}
	return p, nil
}

// UniformFieldElement samples a random element from the underling field for the
// specified elliptic curve.
//
// NOT constant time due to rejection sampling
func (c GroupCurve) UniformFieldElement() (*big.Int, error) {
	var mask = []byte{0xff, 0x1, 0x3, 0x7, 0xf, 0x1f, 0x3f, 0x7f}
	N := c.Order() // base point subgroup order
	bitLen := N.BitLen()
	byteLen := (bitLen + 7) >> 3
	buf := make([]byte, byteLen)

	// rejection sampling
	for true {
		_, err := io.ReadFull(rand.Reader, buf)
		if err != nil {
			return nil, oerr.ErrInternalInstantiation
		}
		// Mask to account for field sizes that are not a whole number of bytes.
		buf[0] &= mask[bitLen%8]
		// Check if scalar is in the correct range.
		if new(big.Int).SetBytes(buf).Cmp(N) >= 0 {
			continue
		}
		break
	}

	return new(big.Int).SetBytes(buf), nil
}

// Name returns the name of the elliptic curve that is being used (e.g. P384).
func (c GroupCurve) Name() string { return c.name }

// Hash returns the name of the hash function used in conjunction with the
// elliptic curve. This is also used when encoding bytes as random elements in
// the curve (as part of the hash-to-curve spec).
func (c GroupCurve) Hash() hash.Hash { return c.hash }

// EE returns the ExtractorExpander function associated with the GroupCurve
// (also used in hash-to-curve).
func (c GroupCurve) EE() utils.ExtractorExpander { return c.ee }

// CurveConstants keeps track of a number of constants that are useful for
// performing elliptic curve operations. In particular, it stores a (where y^2 =
// x^3 - ax + b is assumed to be the curve definition), along with scalar
// exponents that can be used for computing square roots in the underlying
// field.
type CurveConstants struct {
	a, sqrtExp, isSqExp *big.Int
}

// CreateNistCurve creates an instance of a GroupCurve corresponding to a NIST
// elliptic curve (supports P384 or P521).
func CreateNistCurve(curve elliptic.Curve, h hash.Hash, ee utils.ExtractorExpander) GroupCurve {
	name := ""
	switch curve {
	case p384.P384():
		name = "P-384"
	case elliptic.P521():
		name = "P-521"
	}
	p := curve.Params().P
	isSqExp := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Sub(p, constants.One), new(big.Int).ModInverse(constants.Two, p)), p)
	sqrtExp := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Add(p, constants.One), new(big.Int).ModInverse(constants.Four, p)), p)
	return GroupCurve{
		ops:        curve,
		name:       name,
		hash:       h,
		ee:         ee,
		byteLength: (curve.Params().BitSize + 7) / 8,
		nist:       true,
		sgn0:       utils.Sgn0LE,
		consts: CurveConstants{
			a:       constants.MinusThree,
			sqrtExp: sqrtExp,
			isSqExp: isSqExp,
		},
	}
}

// Point implements the GroupElement interface and is compatible with the
// GroupCurve PrimeOrderGroup instantiation. Stored explicit coordinates for
// associating the Point with an elliptic curve. The compress flag dictates
// whether the point is serialized in compressed format, or not.
type Point struct {
	X, Y     *big.Int
	pog      gg.PrimeOrderGroup
	compress bool // indicates that the point should be compressed on serialization.
}

// New returns a new point initialised to constants.Zero
func (p Point) New(pog gg.PrimeOrderGroup) gg.GroupElement {
	return Point{X: constants.Zero, Y: constants.Zero, pog: pog, compress: true}
}

// Equal returns true if the two Point objects have the same X and Y
// coordinates and belong to the same curve. Otherwise it returns false.
func (p Point) Equal(ge gg.GroupElement) bool {
	pEq, err := castToPoint(ge)
	if err != nil {
		return false
	}
	// check that both points are valid
	if !p.IsValid() || !pEq.IsValid() {
		return false
	}
	// check that the supplied Point is valid with respect to the group for p
	pChkGroup := Point{}.New(p.pog).(Point)
	pChkGroup.X = pEq.X
	pChkGroup.Y = pEq.Y
	if !pChkGroup.IsValid() {
		return false
	}

	// check that the point coordinates are the same
	return (p.X.Cmp(pEq.X) == 0) && (p.Y.Cmp(pEq.Y) == 0)
}

// IsValid checks that the given Point object is a valid curve point for the
// input GroupCurve Object
func (p Point) IsValid() bool {
	curve, err := castToCurve(p.pog)
	if err != nil {
		return false
	}
	return curve.ops.IsOnCurve(p.X, p.Y)
}

// ScalarMult multiplies p by the provided Scalar value, and returns p or an
// error.
func (p Point) ScalarMult(k *big.Int) (gg.GroupElement, error) {
	if !p.IsValid() {
		return nil, oerr.ErrInvalidGroupElement
	}
	curve, err := castToCurve(p.pog)
	if err != nil {
		return nil, err
	}
	p.X, p.Y = curve.ops.ScalarMult(p.X, p.Y, k.Bytes())
	return p, nil
}

// Add adds one Point object (pAdd) to the caller Point (p) and returns p or an
// error. This computes the Addition operation in the additive group
// instantiated by the curve.
func (p Point) Add(ge gg.GroupElement) (gg.GroupElement, error) {
	if !p.IsValid() {
		return nil, oerr.ErrInvalidGroupElement
	}
	curve, err := castToCurve(p.pog)
	if err != nil {
		return nil, err
	}
	// retrieve and normalize points
	pAdd, err := castToPoint(ge)
	if err != nil {
		return nil, err
	}
	p.X, p.Y = curve.ops.Add(p.X, p.Y, pAdd.X, pAdd.Y)
	return p, nil
}

// Serialize marshals the point object into an octet-string, returns nil if
// serialization is not supported for the given curve.
func (p Point) Serialize() ([]byte, error) {
	curve, err := castToCurve(p.pog)
	if err != nil {
		return nil, err
	}

	// attempt to deserialize
	if curve.nist {
		buf := p.nistSerialize(curve)
		return buf, nil
	}
	return nil, oerr.ErrUnsupportedGroup
}

// Deserialize unmarshals an octet-string into a valid Point object for the
// specified curve. If the bytes do not correspond to a valid Point then it
// returns an error.
func (p Point) Deserialize(buf []byte) (gg.GroupElement, error) {
	curve, err := castToCurve(p.pog)
	if err != nil {
		return nil, err
	}
	if curve.nist {
		p, err = p.nistDeserialize(curve, buf)
		if err != nil {
			return nil, err
		}
		return p, nil
	}
	return nil, oerr.ErrUnsupportedGroup
}

// nistSerialize marshals the point object into an octet-string of either
// compressed or uncompressed SEC1 format
// (https://www.secg.org/sec1-v2.pdf#subsubsection.2.3.3)
//
// NOT constant time due to variable number of bytes
func (p Point) nistSerialize(curve GroupCurve) []byte {
	xBytes, yBytes := p.X.Bytes(), p.Y.Bytes()
	// append zeroes to the front if the bytes are not filled up
	xBytes = append(make([]byte, curve.ByteLength()-len(xBytes)), xBytes...)
	yBytes = append(make([]byte, curve.ByteLength()-len(yBytes)), yBytes...)

	var bytes []byte
	var tag int
	if !p.compress {
		bytes = append(xBytes, yBytes...)
		tag = 4
	} else {
		bytes = xBytes
		sign := utils.Sgn0LE(p.Y)
		// perform sign-check and cast to int
		e := int(utils.EqualsToBigInt(sign, constants.One).Int64())
		// select correct tag
		tag = subtle.ConstantTimeSelect(e, 2, 3)
	}
	return append([]byte{byte(tag)}, bytes...)
}

// nistDeserialize creates a point object from an octet-string according to the
// SEC1 specification (https://www.secg.org/sec1-v2.pdf#subsubsection.2.3.4)
func (p Point) nistDeserialize(curve GroupCurve, buf []byte) (Point, error) {
	tag := buf[0]
	compressed := false
	byteLength := curve.ByteLength()
	switch tag {
	case 2, 3:
		if byteLength < len(buf)-1 {
			return Point{}, oerr.ErrDeserializing
		}
		compressed = true
		break
	case 4:
		if byteLength*2 < len(buf)-1 {
			return Point{}, oerr.ErrDeserializing
		}
		break
	default:
		return Point{}, oerr.ErrDeserializing
	}

	// deserialize depending on whether point is compressed or not
	if !compressed {
		p.X = new(big.Int).SetBytes(buf[1 : byteLength+1])
		p.Y = new(big.Int).SetBytes(buf[byteLength+1:])
		return p, nil
	}
	return p.nistDecompress(curve, buf)
}

// nistDecompress takes a buffer for an x coordinate as input and attempts to
// construct a valid curve point by re-evaluating the curve equation to
// construct the y coordinate. If it fails it returns an error.
func (p Point) nistDecompress(curve GroupCurve, buf []byte) (Point, error) {
	// recompute curve equation y^2 = x^3 + ax + b
	order := curve.P()
	x := new(big.Int).SetBytes(buf[1:])
	rhs := new(big.Int).Add(new(big.Int).Exp(x, constants.Two, order), constants.MinusThree) // a = -3
	rhs = rhs.Mul(rhs, x)
	rhs = rhs.Add(rhs, curve.ops.Params().B)
	rhs = rhs.Mod(rhs, order)

	// construct y coordinate with correct sign
	y := rhs.Exp(rhs, curve.consts.sqrtExp, order)
	bufParity := utils.EqualsToBigInt(big.NewInt(int64(buf[0])), constants.Two)
	yParity := utils.EqualsToBigInt(utils.Sgn0LE(y), constants.One)
	y = utils.Cmov(new(big.Int).Mul(y, constants.MinusOne), y, utils.EqualsToBigInt(bufParity, yParity))

	// construct point and check validity
	p.X = new(big.Int).Mod(x, curve.P())
	p.Y = new(big.Int).Mod(y, curve.P())
	if !p.IsValid() {
		return Point{}, oerr.ErrInvalidGroupElement
	}
	return p, nil
}

// clearCofactor clears the cofactor (hEff) of the Point p by performing a
// scalar multiplication (with hEff) and returning p or an error
func (p Point) clearCofactor(hEff *big.Int) (Point, error) {
	ret, err := p.ScalarMult(hEff)
	if err != nil {
		return Point{}, err
	}
	// type assertion withour normalization
	point, err := castToPoint(ret)
	if err != nil {
		return Point{}, err
	}
	return point, nil
}

/**
 * Curve utility functions
 */

// castToCurve attempts to cast the input PrimeOrderGroup to a GroupCurve object
func castToCurve(group gg.PrimeOrderGroup) (GroupCurve, error) {
	curve, ok := group.(GroupCurve)
	if !ok {
		return GroupCurve{}, oerr.ErrTypeAssertion
	}
	return curve, nil
}

// castToPoint attempts to cast the input GroupElement to a normalize Point
// object
func castToPoint(ge gg.GroupElement) (Point, error) {
	point, ok := ge.(Point)
	if !ok {
		return Point{}, oerr.ErrTypeAssertion
	}
	if !point.IsValid() {
		return Point{}, oerr.ErrInvalidGroupElement
	}
	return point, nil
}
