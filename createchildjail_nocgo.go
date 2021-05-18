// +build !cgo

package gojail

import (
	"errors"
)

func (*jail) CreateChildJail(map[string]interface{}) (Jail, error) {
	return nil, errors.New("Not implemented")
}
