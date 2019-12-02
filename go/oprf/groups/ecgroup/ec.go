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
	oc "github.com/alxdavids/oprf-poc/go/oprf/oprfCrypto"
	"github.com/cloudflare/circl/ecc/p384"
)

// big.Int constants
var (
	zero, one, minusOne, minusThree, two, four *big.Int = big.NewInt(0), big.NewInt(1), big.NewInt(-1), big.NewInt(-3), big.NewInt(2), big.NewInt(4)
)

// GroupCurve implements the PrimeOrderGroup interface
type GroupCurve struct {
	ops        elliptic.Curve
	name       string
	hash       hash.Hash
	ee         oc.ExtractorExpander
	byteLength int
	nist       bool
	sgn0       func(*big.Int) *big.Int
	consts     CurveConstants
}

// New constructs a new GroupCurve object implementing the PrimeOrderGroup
// interface
func (c GroupCurve) New(name string) (gg.PrimeOrderGroup, oerr.Error) {
	var curve elliptic.Curve
	var h hash.Hash
	var ee oc.ExtractorExpander
	switch name {
	case "P-384":
		curve = p384.P384()
		h = sha512.New()
		ee = oc.HKDFExtExp{}
		break
	case "P-521":
		curve = elliptic.P521()
		h = sha512.New()
		ee = oc.HKDFExtExp{}
		break
	default:
		return nil, oerr.ErrUnsupportedGroup
	}
	p := curve.Params().P
	isSqExp := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Sub(p, one), new(big.Int).ModInverse(two, p)), p)
	sqrtExp := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Add(p, one), new(big.Int).ModInverse(four, p)), p)
	return GroupCurve{
		ops:        curve,
		name:       name,
		hash:       h,
		ee:         ee,
		byteLength: (curve.Params().BitSize + 7) / 8,
		nist:       true,
		sgn0:       sgn0LE,
		consts: CurveConstants{
			a:       minusThree,
			sqrtExp: sqrtExp,
			isSqExp: isSqExp,
		},
	}, oerr.Nil()
}

// Order returns the order of the base point for the base curve object
func (c GroupCurve) Order() *big.Int {
	return c.ops.Params().N
}

// P returns the order of the underlying field for the base curve object
func (c GroupCurve) P() *big.Int {
	return c.ops.Params().P
}

// Generator returns the point in the curve representing the generator for the
// instantiated prime-order group
func (c GroupCurve) Generator() gg.GroupElement {
	G := Point{}.New(c).(Point)
	G.X = c.ops.Params().Gx
	G.Y = c.ops.Params().Gy
	return G
}

// GeneratorMult returns k*G, where G is the generator of the curve
func (c GroupCurve) GeneratorMult(k *big.Int) (gg.GroupElement, oerr.Error) {
	G := c.Generator()
	return G.ScalarMult(k)
}

// ByteLength returns the length, in bytes, of a valid representation of a group
// element
func (c GroupCurve) ByteLength() int {
	return c.byteLength
}

// EncodeToGroup invokes the hash_to_curve method for encoding bytes as curve
// points
func (c GroupCurve) EncodeToGroup(buf []byte) (gg.GroupElement, oerr.Error) {
	params, err := getH2CParams(c)
	if err.Err() != nil {
		return nil, err
	}
	p, err := params.hashToCurve(buf)
	if err.Err() != nil {
		return nil, err
	}
	return p.normalize()
}

// UniformFieldElement samples a random element from the underling field for the
// choice of curve
func (c GroupCurve) UniformFieldElement() (*big.Int, oerr.Error) {
	// This is just a bitmask with the number of ones starting at 8 then
	// incrementing by index. To account for fields with bitsizes that are not a whole
	// number of bytes, we mask off the unnecessary bits. h/t agl
	var mask = []byte{0xff, 0x1, 0x3, 0x7, 0xf, 0x1f, 0x3f, 0x7f}
	N := c.ops.Params().N // base point subgroup order
	bitLen := N.BitLen()
	byteLen := (bitLen + 7) >> 3
	buf := make([]byte, byteLen)

	// When in doubt, do what agl does in elliptic.go. Presumably
	// new(big.Int).SetBytes(b).Mod(N) would introduce bias, so we're sampling.
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

	return new(big.Int).SetBytes(buf), oerr.Nil()
}

// Name returns the name of the NIST P-384 curve
func (c GroupCurve) Name() string { return c.name }

// Hash returns the name of the hash function used in conjunction with the NIST
// P-384 curve
func (c GroupCurve) Hash() hash.Hash { return c.hash }

// EE returns the ExtractorExpander function associated with the GroupCurve
func (c GroupCurve) EE() oc.ExtractorExpander { return c.ee }

// CurveConstants keeps track of a number of constants that are useful for
// performing elliptic curve operations
type CurveConstants struct {
	a, sqrtExp, isSqExp *big.Int
}

// CreateNistCurve creates an instance of a GroupCurve corresponding to a NIST
// elliptic curve
func CreateNistCurve(curve elliptic.Curve, h hash.Hash, ee oc.ExtractorExpander) GroupCurve {
	name := ""
	switch curve {
	case p384.P384():
		name = "P-384"
	case elliptic.P521():
		name = "P-521"
	}
	p := curve.Params().P
	isSqExp := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Sub(p, one), new(big.Int).ModInverse(two, p)), p)
	sqrtExp := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Add(p, one), new(big.Int).ModInverse(four, p)), p)
	return GroupCurve{
		ops:        curve,
		name:       name,
		hash:       h,
		ee:         ee,
		byteLength: (curve.Params().BitSize + 7) / 8,
		nist:       true,
		sgn0:       sgn0LE,
		consts: CurveConstants{
			a:       minusThree,
			sqrtExp: sqrtExp,
			isSqExp: isSqExp,
		},
	}
}

// Point implements the Group interface and is compatible with the Curve
// Group-type
type Point struct {
	X, Y     *big.Int
	pog      gg.PrimeOrderGroup
	compress bool // indicates that the point should be compressed on serialization.
}

// New returns a new point initialised to zero
func (p Point) New(pog gg.PrimeOrderGroup) gg.GroupElement {
	return Point{X: zero, Y: zero, pog: pog, compress: true}
}

// Equal returns true if the two Point objects have the same X and Y
// coordinates, and false otherwise (normalizes by default)
func (p Point) Equal(ge gg.GroupElement) bool {
	pEq, err := castToPoint(ge)
	if err.Err() != nil {
		return false
	}
	return p.equalWN(pEq)
}

// IsValid checks that the given point is a valid curve point for the input
// GroupCurve Object
func (p Point) IsValid() bool {
	curve, err := castToCurve(p.pog)
	if err.Err() != nil {
		return false
	}
	return curve.ops.IsOnCurve(p.X, p.Y)
}

// ScalarMult multiplies p by the provided Scalar value, and returns p or an
// oerr.Error, normalizes by default
func (p Point) ScalarMult(k *big.Int) (gg.GroupElement, oerr.Error) {
	if !p.IsValid() {
		return nil, oerr.ErrInvalidGroupElement
	}
	curve, err := castToCurve(p.pog)
	if err.Err() != nil {
		return nil, err
	}
	// normalize point and perform multiplication
	p, err = p.normalize()
	if err.Err() != nil {
		return nil, err
	}
	p.X, p.Y = curve.ops.ScalarMult(p.X, p.Y, k.Bytes())
	return p.normalize()
}

// Add adds pAdd to p and returns p or an oerr.Error, normalizes by default
func (p Point) Add(ge gg.GroupElement) (gg.GroupElement, oerr.Error) {
	if !p.IsValid() {
		return nil, oerr.ErrInvalidGroupElement
	}
	curve, err := castToCurve(p.pog)
	if err.Err() != nil {
		return nil, err
	}
	// retrieve and normalize points
	pAdd, err := castToPoint(ge)
	if err.Err() != nil {
		return nil, err
	}
	p, err = p.normalize()
	if err.Err() != nil {
		return nil, err
	}
	pAdd, err = pAdd.normalize()
	if err.Err() != nil {
		return nil, err
	}
	p.X, p.Y = curve.ops.Add(p.X, p.Y, pAdd.X, pAdd.Y)
	return p.normalize()
}

// Serialize marshals the point object into an octet-string, returns nil if
// serialization is not supported for the given curve
func (p Point) Serialize() ([]byte, oerr.Error) {
	curve, err := castToCurve(p.pog)
	if err.Err() != nil {
		return nil, err
	}

	// attempt to deserialize
	if curve.nist {
		p, err := p.normalize()
		if err.Err() != nil {
			return nil, err
		}
		return p.nistSerialize(curve), oerr.Nil()
	}
	return nil, oerr.ErrUnsupportedGroup
}

// Deserialize unmarshals an octet-string into a valid point on curve
func (p Point) Deserialize(buf []byte) (gg.GroupElement, oerr.Error) {
	curve, err := castToCurve(p.pog)
	if err.Err() != nil {
		return nil, err
	}
	if curve.nist {
		p, err = p.nistDeserialize(curve, buf)
		if err.Err() != nil {
			return nil, err
		}
		return p.normalize()
	}
	return nil, oerr.ErrUnsupportedGroup
}

// normalize returns the Point object with normalized coordinates
func (p Point) normalize() (Point, oerr.Error) {
	curve, err := castToCurve(p.pog)
	if err.Err() != nil {
		return Point{}, err
	}
	p.X = new(big.Int).Mod(p.X, curve.P())
	p.Y = cmov(p.Y, new(big.Int).Mul(p.Y, minusOne), equalsToBigInt(sgn0LE(p.Y), minusOne))
	p.Y = p.Y.Mod(p.Y, curve.P())
	return p, oerr.Nil()
}

// equalWN performs Point equality test without nomalization
func (p Point) equalWN(pEq Point) bool {
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

// addWN adds two points together without performing normalization (used by H2C)
func (p Point) addWN(pAdd Point) (Point, oerr.Error) {
	if !p.IsValid() {
		return Point{}, oerr.ErrInvalidGroupElement
	}
	curve, err := castToCurve(p.pog)
	if err.Err() != nil {
		return Point{}, err
	}
	p.X, p.Y = curve.ops.Add(p.X, p.Y, pAdd.X, pAdd.Y)
	return p, oerr.Nil()
}

// scalarMultWN performs multiplication of P by scalar k without
// normalizing the resulting point
func (p Point) scalarMultWN(k *big.Int) (gg.GroupElement, oerr.Error) {
	if !p.IsValid() {
		return nil, oerr.ErrInvalidGroupElement
	}
	curve, err := castToCurve(p.pog)
	if err.Err() != nil {
		return nil, err
	}
	p.X, p.Y = curve.ops.ScalarMult(p.X, p.Y, k.Bytes())
	return p, oerr.Nil()
}

// nistSerialize marshals the point object into an octet-string of either
// compressed or uncompressed SEC1 format
// (https://www.secg.org/sec1-v2.pdf#subsubsection.2.3.3)
//
// NOT CONSTANT-TIME due to variable number of bytes
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
		tag = subtle.ConstantTimeSelect(int(yBytes[0])&1, 3, 2)
	}
	return append([]byte{byte(tag)}, bytes...)
}

// nistDeserialize creates a point object from an octet-string according to the
// SEC1 specification (https://www.secg.org/sec1-v2.pdf#subsubsection.2.3.4)
func (p Point) nistDeserialize(curve GroupCurve, buf []byte) (Point, oerr.Error) {
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

	// deserailize depending on whether point is compressed or not
	if !compressed {
		p.X = new(big.Int).SetBytes(buf[1 : byteLength+1])
		p.Y = new(big.Int).SetBytes(buf[byteLength+1:])
		return p, oerr.Nil()
	}
	return p.nistDecompress(curve, buf)
}

// nistDecompress takes a buffer for an x coordinate as input and attempts to
// construct a valid curve point by re-evaluating the curve equation to
// construct the y coordinate
func (p Point) nistDecompress(curve GroupCurve, buf []byte) (Point, oerr.Error) {
	// recompute sign
	sign := buf[0] & 1

	// recompute curve equation y^2 = x^3 + ax + b
	order := curve.P()
	x := new(big.Int).SetBytes(buf[1:])
	rhs := new(big.Int).Add(new(big.Int).Exp(x, two, order), minusThree) // a = -3
	rhs = rhs.Mul(rhs, x)
	rhs = rhs.Add(rhs, curve.ops.Params().B)
	rhs = rhs.Mod(rhs, order)

	// construct y coordinate
	y := rhs.Exp(rhs, curve.consts.sqrtExp, order)
	parity := sgn0LE(y)
	e := sgnCmp(parity, big.NewInt(int64(sign)), sgn0LE)
	y = cmov(new(big.Int).Mul(y, minusOne), y, e)

	// construct point and check validity
	p.X = x
	p.Y = y
	if !p.IsValid() {
		return Point{}, oerr.ErrInvalidGroupElement
	}
	return p, oerr.Nil()
}

// clearCofactor clears the cofactor (hEff) of p by performing a scalar
// multiplication and returning p or an oerr.Error
func (p Point) clearCofactor(hEff *big.Int) (Point, oerr.Error) {
	ret, err := p.scalarMultWN(hEff)
	if err.Err() != nil {
		return Point{}, err
	}
	// type assertion withour normalization
	point, ok := ret.(Point)
	if !ok {
		return Point{}, oerr.ErrTypeAssertion
	}
	return point, oerr.Nil()
}

/**
 * Curve utility functions
 */

// castToCurve attempts to cast the input PrimeOrderGroup to a GroupCurve object
func castToCurve(group gg.PrimeOrderGroup) (GroupCurve, oerr.Error) {
	curve, ok := group.(GroupCurve)
	if !ok {
		return GroupCurve{}, oerr.ErrTypeAssertion
	}
	return curve, oerr.Nil()
}

// castToPoint attempts to cast the input GroupElement to a normalize Point
// object
func castToPoint(ge gg.GroupElement) (Point, oerr.Error) {
	point, ok := ge.(Point)
	if !ok {
		return Point{}, oerr.ErrTypeAssertion
	}
	if !point.IsValid() {
		return Point{}, oerr.ErrInvalidGroupElement
	}
	point, err := point.normalize()
	if err.Err() != nil {
		return Point{}, err
	}
	return point, oerr.Nil()
}

// cmpToBigInt converts the return value from a comparison operation into a
// *big.Int
func cmpToBigInt(a, b *big.Int) *big.Int {
	return big.NewInt(int64(a.Cmp(b)))
}

// equalsToBigInt returns big.Int(1) if a == b and big.Int(0) otherwise
func equalsToBigInt(a, b *big.Int) *big.Int {
	cmp := cmpToBigInt(a, b)
	equalsRev := new(big.Int).Abs(cmp)
	return revCmpBit(equalsRev)
}

// returns 1 if the signs of s1 and s2 are the same, and 0 otherwise
func sgnCmp(s1, s2 *big.Int, sgn0 func(*big.Int) *big.Int) *big.Int {
	return equalsToBigInt(sgn0(s1), sgn0(s2))
}

// sgn0LE returns -1 if x is negative (in little-endian sense) and 1 if x is positive
func sgn0LE(x *big.Int) *big.Int {
	res := equalsToBigInt(new(big.Int).Mod(x, two), one)
	sign := cmov(one, minusOne, res)
	zeroCmp := equalsToBigInt(x, zero)
	sign = cmov(sign, zero, zeroCmp)
	sZeroCmp := equalsToBigInt(sign, zero)
	return cmov(sign, one, sZeroCmp)
}

// cmov is a constant-time big.Int conditional selector, returning b if c is 1,
// and a if c = 0
func cmov(a, b, c *big.Int) *big.Int {
	return new(big.Int).Add(new(big.Int).Mul(c, b), new(big.Int).Mul(new(big.Int).Sub(one, c), a))
}
