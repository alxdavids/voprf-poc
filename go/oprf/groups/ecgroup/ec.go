package ecgroup

import (
	"crypto/elliptic"
	"crypto/sha512"
	"crypto/subtle"
	"hash"
	"math/big"

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
func (c GroupCurve) New(name string) (gg.PrimeOrderGroup, error) {
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
		return GroupCurve{}, gg.ErrUnsupportedGroup
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
	}, nil
}

// Order returns the order of the underlying field for the base curve object
func (c GroupCurve) Order() *big.Int {
	return c.ops.Params().P
}

// Generator returns the point in the curve representing the generator for the
// instantiated prime-order group
func (c GroupCurve) Generator() gg.GroupElement {
	return Point{
		X: c.ops.Params().Gx,
		Y: c.ops.Params().Gy,
	}
}

// GeneratorMult returns k*G, where G is the generator of the curve
func (c GroupCurve) GeneratorMult(k *big.Int) (gg.GroupElement, error) {
	G := c.Generator()
	return G.ScalarMult(c, k)
}

// ByteLength returns the length, in bytes, of a valid representation of a group
// element
func (c GroupCurve) ByteLength() int {
	return c.byteLength
}

// EncodeToGroup invokes the hash_to_curve method for encoding bytes as curve
// points
func (c GroupCurve) EncodeToGroup(buf []byte) (gg.GroupElement, error) {
	params, err := getH2CParams(c)
	if err != nil {
		return Point{}, err
	}
	p, err := params.hashToCurve(buf)
	if err != nil {
		return Point{}, err
	}
	return p, nil
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
	compress bool // indicates that the point should be compressed on serialization.
}

// New returns a new point intiialised to zero
func (p Point) New() gg.GroupElement {
	return Point{X: zero, Y: zero, compress: false}
}

// IsValid checks that the given point is a valid curve point for the input
// GroupCurve Object
func (p Point) IsValid(group gg.PrimeOrderGroup) bool {
	curve, ok := group.(GroupCurve)
	if !ok {
		return false
	}
	return curve.ops.IsOnCurve(p.X, p.Y)
}

// ScalarMult multiplies p by the provided Scalar value, and returns p or an
// error
func (p Point) ScalarMult(group gg.PrimeOrderGroup, k *big.Int) (gg.GroupElement, error) {
	if !p.IsValid(group) {
		return Point{}, gg.ErrInvalidGroupElement
	}
	curve, ok := group.(GroupCurve)
	if !ok {
		return Point{}, gg.ErrTypeAssertion
	}
	p.X, p.Y = curve.ops.ScalarMult(p.X, p.Y, k.Bytes())
	return p, nil
}

// Add adds pAdd to p and returns p or an error
func (p Point) Add(group gg.PrimeOrderGroup, ge gg.GroupElement) (gg.GroupElement, error) {
	if !p.IsValid(group) {
		return Point{}, gg.ErrInvalidGroupElement
	}
	curve, err := castToCurve(group)
	if err != nil {
		return Point{}, err
	}
	pAdd, err := castToPoint(ge)
	if err != nil {
		return Point{}, err
	}
	p.X, p.Y = curve.ops.Add(p.X, p.Y, pAdd.X, pAdd.Y)
	return p, nil
}

// Serialize marshals the point object into an octet-string, returns nil if
// serialization is not supported for the given curve
func (p Point) Serialize(group gg.PrimeOrderGroup) ([]byte, error) {
	curve, ok := group.(GroupCurve)
	if !ok {
		return nil, gg.ErrTypeAssertion
	}

	// attempt to deserialize
	if curve.nist {
		return p.nistSerialize(), nil
	}
	return nil, gg.ErrUnsupportedGroup
}

// Deserialize unmarshals an octet-string into a valid point on curve
func (p Point) Deserialize(group gg.PrimeOrderGroup, buf []byte) (gg.GroupElement, error) {
	curve, err := castToCurve(group)
	if err != nil {
		return Point{}, err
	}
	if curve.nist {
		return p.nistDeserialize(curve, buf)
	}
	return Point{}, gg.ErrUnsupportedGroup
}

// nistSerialize marshals the point object into an octet-string of either
// compressed or uncompressed SEC1 format
// (https://www.secg.org/sec1-v2.pdf#subsubsection.2.3.3)
func (p Point) nistSerialize() []byte {
	xBytes, yBytes := p.X.Bytes(), p.Y.Bytes()
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
func (p Point) nistDeserialize(curve GroupCurve, buf []byte) (Point, error) {
	tag := buf[0]
	compressed := false
	byteLength := curve.ByteLength()
	switch tag {
	case 2, 3:
		if byteLength != len(buf)-1 {
			return Point{}, gg.ErrDeserializing
		}
		compressed = true
		break
	case 4:
		if byteLength*2 != len(buf)-1 {
			return Point{}, gg.ErrDeserializing
		}
		break
	default:
		return Point{}, gg.ErrDeserializing
	}

	// deserailize depending on whether point is compressed or not
	if !compressed {
		p.X = new(big.Int).SetBytes(buf[1 : byteLength+1])
		p.Y = new(big.Int).SetBytes(buf[byteLength+1:])
		return p, nil
	}
	return p.nistDecompress(curve, buf)
}

// nistDecompress takes a buffer for an x coordinate as input and attempts to
// construct a valid curve point by re-evaluating the curve equation to
// construct the y coordinate
func (p Point) nistDecompress(curve GroupCurve, buf []byte) (Point, error) {
	// recompute sign
	sign := buf[0] & 1

	// recompute curve equation y^2 = x^3 + ax + b
	order := curve.Order()
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
	if !p.IsValid(curve) {
		return Point{}, gg.ErrInvalidGroupElement
	}
	return p, nil
}

// clearCofactor clears the cofactor (hEff) of p by performing a scalar
// multiplication and returning p or an error
func (p Point) clearCofactor(curve GroupCurve, hEff *big.Int) (Point, error) {
	ret, err := p.ScalarMult(curve, hEff)
	if err != nil {
		return Point{}, err
	}
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
		return GroupCurve{}, gg.ErrTypeAssertion
	}
	return curve, nil
}

// castToCurve attempts to cast the input GroupElement to a Point object
func castToPoint(ge gg.GroupElement) (Point, error) {
	point, ok := ge.(Point)
	if !ok {
		return Point{}, gg.ErrTypeAssertion
	}
	return point, nil
}

// returns 1 if the signs of s1 and s2 are the same, and 0 otherwise
func sgnCmp(s1, s2 *big.Int, sgn0 func(*big.Int) *big.Int) *big.Int {
	return equalsToBigInt(sgn0(s1), sgn0(s2))
}

// sgn0LE returns -1 if x is negative (in little-endian sense) and 0/1 if x is positive
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
