package utils

import (
	"fmt"
	"math/big"

	"github.com/alxdavids/voprf-poc/go/oerr"
)

// I2osp converts an integer to an octet-string
// (https://tools.ietf.org/html/rfc8017#section-4.1)
func I2osp(x, xLen int) ([]byte, error) {
	if x < 0 || x >= (1<<(8*xLen)) {
		return nil, oerr.ErrInternalInstantiation
	}
	ret := make([]byte, xLen)
	val := x
	for i := xLen - 1; i >= 0; i-- {
		ret[i] = byte(val & 0xff)
		val >>= 8
	}
	return ret, nil
}

// Os2ip converts an octet-string to an integer
// (https://tools.ietf.org/html/rfc8017#section-4.1)
func Os2ip(x []byte) *big.Int {
	return new(big.Int).SetBytes(x)
}

type serializer interface {
	Serialize() ([]byte, error)
}

func ByteSliceLengthPrefixed(vals ...interface{}) ([]byte, error) {
	result := make([]byte, 0)

	var raw, prefix []byte
	var err error
	for _, val := range vals {
		switch typed := val.(type) {
		case serializer:
			raw, err = typed.Serialize()
			if err != nil {
				return nil, err
			}
			prefix, err = I2osp(len(raw), 2)
		case []byte:
			raw = typed
			prefix, err = I2osp(len(raw), 2)
		case int:
			raw = nil
			prefix, err = I2osp(typed, 2)
		case string:
			raw = []byte(typed)
			prefix, err = I2osp(len(raw), 2)
		default:
			return nil, fmt.Errorf("cannot convert type %T to byte slice", typed)
		}
		if err != nil {
			return nil, err
		}
		result = append(result, append(prefix, raw...)...)
	}

	return result, nil
}
