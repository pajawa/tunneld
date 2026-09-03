//go:build !darwin

package rsd

import "context"

const platformHasRsdInterfaceClassifier = false

func platformRsdInterfaceRole(context.Context, string) (rsdInterfaceRole, error) {
	return rsdInterfaceUnknown, nil
}
