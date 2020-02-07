package ecgroup

import (
	"github.com/alxdavids/voprf-poc/go/oerr"
	h2c "github.com/armfazh/h2c-go-ref"
)

// HashToPoint produces a point by hashing the input message.
type HashToPoint interface {
	Hash(msg []byte) (Point, error)
}

type hasher2point struct {
	GroupCurve
	h2c.HashToPoint
	dst []byte
}

func (h hasher2point) Hash(msg []byte) (Point, error) {
	Q := h.HashToPoint.Hash(msg, h.dst)
	P := Point{}.New(h.GroupCurve).(Point)
	X := Q.X().Polynomial()
	Y := Q.Y().Polynomial()
	P.X.Set(X[0])
	P.Y.Set(Y[0])
	if !P.IsValid() {
		return Point{}, oerr.ErrInvalidGroupElement
	}
	return P, nil
}

func getH2CSuite(gc GroupCurve) (HashToPoint, error) {
	var suite h2c.SuiteID
	var err error
	switch gc.Name() {
	case "P-384":
		suite = h2c.P384_SHA512_SSWU_RO_
	case "P-521":
		suite = h2c.P521_SHA512_SSWU_RO_
	default:
		return nil, oerr.ErrUnsupportedGroup
	}
	dst := append([]byte("RFCXXXX-VOPRF-"), suite...)
	hasher, err := suite.Get()
	if err != nil {
		return nil, err
	}
	return hasher2point{gc, hasher, dst}, nil
}
