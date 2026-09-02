//go:build !darwin

package rsd

import "context"

func platformRsdInterfaceRole(context.Context, string) (rsdInterfaceRole, error) {
	return rsdInterfaceUnknown, nil
}
