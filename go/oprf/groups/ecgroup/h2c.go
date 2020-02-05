package ecgroup

import (
	"fmt"
	"hash"
	"math/big"

	"github.com/alxdavids/voprf-poc/go/oerr"
	"github.com/alxdavids/voprf-poc/go/oprf/utils"
	"github.com/alxdavids/voprf-poc/go/oprf/utils/constants"
)

// h2cParams contains all of the parameters required for computing the
// hash_to_curve mapping algorithm, see
// https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-05 for more
// information.
type h2cParams struct {
	gc      GroupCurve
	name    string
	dst     []byte
	z       int
	a       *big.Int
	b       *big.Int
	p       *big.Int
	m       int
	hash    hash.Hash
	ee      utils.ExtractorExpander
	l       int
	hEff    *big.Int
	isSqExp *big.Int
	sqrtExp *big.Int
	sgn0    func(*big.Int) *big.Int
}

// getH2CParams returns the h2cParams object for the specified curve
func getH2CParams(gc GroupCurve) (h2cParams, error) {
	h2cName := "SSWU-RO"
	params := h2cParams{
		gc:      gc,
		name:    h2cName,
		a:       gc.consts.a,
		b:       gc.ops.Params().B,
		p:       gc.P(),
		hash:    gc.Hash(),
		ee:      gc.ee,
		isSqExp: gc.consts.isSqExp,
		sqrtExp: gc.consts.sqrtExp,
		sgn0:    gc.sgn0,
	}
	switch gc.Name() {
	case "P-384":
		params.dst = []byte(fmt.Sprintf("VOPRF-P384-SHA512-%s-", h2cName))
		params.z = -12
		params.m = 1
		params.l = 72
		params.hEff = constants.One
		break
	case "P-521":
		params.dst = []byte(fmt.Sprintf("VOPRF-P521-SHA512-%s-", h2cName))
		params.z = -4
		params.m = 1
		params.l = 96
		params.hEff = constants.One
		break
	default:
		return h2cParams{}, oerr.ErrUnsupportedGroup
	}
	return params, nil
}

// hashToBase hashes a buffer into a vector of underlying base field elements,
// where the base field is chosen depending on the associated elliptic curve
func (params h2cParams) hashToBaseField(buf []byte, ctr int) ([]*big.Int, error) {
	os, err := utils.I2osp(0, 1)
	if err != nil {
		return nil, oerr.ErrInternalInstantiation
	}
	hashFunc := func() hash.Hash {
		hash := params.hash
		hash.Reset()
		return hash
	}
	extractor := params.ee.Extractor()
	msgPrime := extractor(hashFunc, append(buf, os...), params.dst)
	osCtr, err := utils.I2osp(ctr, 1)
	if err != nil {
		return nil, oerr.ErrInternalInstantiation
	}
	infoPfx := append([]byte("H2C"), osCtr...)
	i := 1
	res := make([]*big.Int, params.m)
	expander := params.ee.Expander()
	for i <= params.m {
		osi, err := utils.I2osp(i, 1)
		if err != nil {
			return nil, oerr.ErrInternalInstantiation
		}
		info := append(infoPfx, osi...)
		reader := expander(hashFunc, msgPrime, info)
		t := make([]byte, params.l)
		reader.Read(t)
		ei := utils.Os2ip(t)
		res[i-1] = new(big.Int).Mod(ei, params.p)
		i++
	}
	return res, nil
}

// hashToCurve hashes a buffer to a curve point on the chosen curve, this
// function can be modelled as a random oracle.
func (params h2cParams) hashToCurve(alpha []byte) (Point, error) {
	// attempt to encode bytes as curve point
	R := Point{}.New(params.gc).(Point)
	switch params.name {
	case "SSWU-RO":
		// See https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-05#section-6.6.1
		u0, err := params.hashToBaseField(alpha, 0)
		if err != nil {
			return Point{}, err
		}
		u1, err := params.hashToBaseField(alpha, 1)
		if err != nil {
			return Point{}, err
		}
		Q0, err := params.sswu(u0)
		if err != nil {
			return Point{}, err
		}
		Q1, err := params.sswu(u1)
		if err != nil {
			return Point{}, err
		}
		geR, err := Q0.Add(Q1)
		if err != nil {
			return Point{}, err
		}
		R, err = castToPoint(geR)
		if err != nil {
			return Point{}, err
		}
		break
	default:
		return Point{}, oerr.ErrIncompatibleGroupParams
	}

	// construct the output point R
	P, err := R.clearCofactor(params.hEff)
	if err != nil {
		return Point{}, err
	}
	return P, nil
}

// sswu completes the Simplified SWU method curve mapping defined in
// https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-05#section-6.6.2
func (params h2cParams) sswu(uArr []*big.Int) (Point, error) {
	if len(uArr) > 1 {
		return Point{}, oerr.ErrIncompatibleGroupParams
	}
	u := uArr[0]
	p, A, B, Z := params.p, params.a, params.b, big.NewInt(int64(params.z))

	// consts
	// c1 := -B/A, c2 := -1/Z
	c1 := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Mul(B, constants.MinusOne), new(big.Int).ModInverse(A, p)), p)
	c2 := new(big.Int).Mul(constants.MinusOne, new(big.Int).ModInverse(Z, p))

	// steps
	t1 := new(big.Int).Mul(Z, new(big.Int).Exp(u, constants.Two, p)) // 1.     t1 = Z * u^2
	t2 := new(big.Int).Exp(t1, constants.Two, p)                     // 2.     t2 = t1^2
	x1 := new(big.Int).Add(t1, t2)                                   // 3.     x1 = t1 + t2
	x1 = utils.Inv0(x1, p)                                           // 4.     x1 = utils.Inv0(x1)
	e1 := utils.EqualsToBigInt(x1, constants.Zero)                   // 5.     e1 = x1 == 0
	x1 = x1.Add(x1, constants.One)                                   // 6.     x1 = x1 + 1
	x1 = utils.Cmov(x1, c2, e1)                                      // 7.     x1 = CMOV(x1, c2, e1)
	x1 = x1.Mul(x1, c1)                                              // 8.     x1 = x1 * c1
	gx1 := new(big.Int).Exp(x1, constants.Two, p)                    // 9.    gx1 = x1^2
	gx1 = gx1.Add(gx1, A)                                            // 10.   gx1 = gx1 + A
	gx1 = gx1.Mul(gx1, x1)                                           // 11.   gx1 = gx1 * x1
	gx1 = gx1.Add(gx1, B)                                            // 12.   gx1 = gx1 + B
	x2 := new(big.Int).Mul(t1, x1)                                   // 13.    x2 = t1 * x1
	t2 = t2.Mul(t1, t2)                                              // 14.    t2 = t1 * t2
	gx2 := new(big.Int).Mul(gx1, t2)                                 // 15.   gx2 = gx1 * t2
	e2 := isSquare(gx1, params.isSqExp, p)                           // 16.    e2 = is_square(gx1)
	x := utils.Cmov(x2, x1, e2)                                      // 17.     x = CMOV(x2, x1, e2)
	y2 := utils.Cmov(gx2, gx1, e2)                                   // 18.    y2 = CMOV(gx2, gx1, e2)
	y := sqrt(y2, params.sqrtExp, p)                                 // 19.     y = sqrt(y2)
	e3 := utils.SgnCmp(u, y, params.sgn0)                            // 20.    e3 = sgn0(u) == sgn0(y)
	y = utils.Cmov(new(big.Int).Mul(y, constants.MinusOne), y, e3)   // 21.     y = CMOV(-y, y, e3)

	// construct point and assert that it is correct
	P := Point{}.New(params.gc).(Point)
	P.X = x.Mod(x, p)
	P.Y = y.Mod(y, p)
	if !P.IsValid() {
		return Point{}, oerr.ErrInvalidGroupElement
	}
	return P, nil
}

// sqrt computes the sqrt of x mod p (pass in exp explicitly so that we don't
// have to recompute)
func sqrt(x, exp, p *big.Int) *big.Int {
	x = x.Mod(x, p)
	y := new(big.Int).Exp(x, exp, p)
	return y
}

// isSquare returns 1 if x is a square integer in FF_p and 0 otherwise, passes
// in the value exp to compute the square root in the exponent
func isSquare(x, exp, p *big.Int) *big.Int {
	b := new(big.Int).Exp(x, exp, p)
	c := b.Cmp(constants.One)
	d := b.Cmp(constants.Zero)
	e := int64(c * d)
	return utils.EqualsToBigInt(big.NewInt(e), constants.Zero) // returns 1 if square, and 0 otherwise
}
