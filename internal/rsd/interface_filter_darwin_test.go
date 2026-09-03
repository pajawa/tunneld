//go:build darwin

package rsd

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseDarwinInterfaceRoles(t *testing.T) {
	output, err := os.ReadFile("testdata/ioreg_iphone.txt")
	require.NoError(t, err)

	roles, err := parseDarwinInterfaceRoles(output)
	require.NoError(t, err)

	assert.Equal(t, rsdInterfacePublic, roles["en48"])
	assert.Equal(t, rsdInterfaceRemoted, roles["en43"])
	assert.NotContains(t, roles, "en36")
	assert.Equal(t, rsdInterfaceUnrelated, darwinInterfaceRole(roles, "en0"))
	assert.Equal(t, rsdInterfaceUnrelated, darwinInterfaceRole(roles, "en36"))
}

func TestParseDarwinInterfaceRolesLeavesIncompletePairUnknown(t *testing.T) {
	output := []byte(`
+-o iPhone@00100000  <class IOUSBHostDevice, id 0x1>
  | {
  |   "idVendor" = 1452
  | }
  +-o Control@3  <class IOUSBHostInterface, id 0x2>
  | | {
  | |   "bInterfaceClass" = 2
  | |   "bInterfaceSubClass" = 13
  | |   "bInterfaceNumber" = 3
  | | }
  +-o Data@4  <class IOUSBHostInterface, id 0x3>
  | | {
  | |   "bInterfaceClass" = 10
  | |   "bInterfaceNumber" = 4
  | | }
  | +-o en25  <class IOEthernetInterface, id 0x4>
  |       {
  |         "BSD Name" = "en25"
  |       }
`)

	roles, err := parseDarwinInterfaceRoles(output)
	require.NoError(t, err)
	assert.Equal(t, rsdInterfaceUnknown, roles["en25"])
}

func TestParseDarwinInterfaceRolesFailsOpenWithoutHiddenMarker(t *testing.T) {
	output, err := os.ReadFile("testdata/ioreg_iphone.txt")
	require.NoError(t, err)
	output = []byte(strings.ReplaceAll(string(output), `"HiddenInterface" = Yes`, `"HiddenConfiguration" = Yes`))

	roles, err := parseDarwinInterfaceRoles(output)
	require.NoError(t, err)
	assert.Equal(t, rsdInterfaceUnknown, roles["en48"])
	assert.Equal(t, rsdInterfaceUnknown, roles["en43"])
}

func TestParseDarwinInterfaceRolesNormalizesPropertyValues(t *testing.T) {
	output, err := os.ReadFile("testdata/ioreg_iphone.txt")
	require.NoError(t, err)
	output = []byte(strings.ReplaceAll(string(output), `"BSD Name" = "en48"`, `"BSD Name" = en48`))
	output = []byte(strings.ReplaceAll(string(output), `"HiddenInterface" = Yes`, `"HiddenInterface" = "Yes"`))

	roles, err := parseDarwinInterfaceRoles(output)
	require.NoError(t, err)
	assert.Equal(t, rsdInterfacePublic, roles["en48"])
	assert.Equal(t, rsdInterfaceRemoted, roles["en43"])
}

func TestParseDarwinInterfaceRolesRejectsIncompleteAppleNCMTree(t *testing.T) {
	output, err := os.ReadFile("testdata/ioreg_iphone.txt")
	require.NoError(t, err)
	output = []byte(strings.ReplaceAll(string(output), `"BSD Name"`, `"Interface Name"`))

	_, err = parseDarwinInterfaceRoles(output)
	require.ErrorContains(t, err, "has no BSD name")
}

func TestParseDarwinInterfaceRolesRejectsMalformedSnapshot(t *testing.T) {
	_, err := parseDarwinInterfaceRoles([]byte(`"idVendor" = 1452`))
	require.ErrorContains(t, err, "no IOUSBHostDevice nodes found")
}

func TestDescendantUSBHostInterfacesAllowsIntermediaryNodes(t *testing.T) {
	wanted := &ioregNode{class: "IOUSBHostInterface"}
	nestedDeviceInterface := &ioregNode{class: "IOUSBHostInterface"}
	root := &ioregNode{
		class: "IOUSBHostDevice",
		children: []*ioregNode{
			{class: "CompositeDriver", children: []*ioregNode{wanted}},
			{class: "IOUSBHostDevice", children: []*ioregNode{nestedDeviceInterface}},
		},
	}

	assert.Equal(t, []*ioregNode{wanted}, descendantUSBHostInterfaces(root))
}

func TestRetryDarwinInterfaceRoleRetriesNegativeResult(t *testing.T) {
	calls := 0
	lookup := func(context.Context, string) (rsdInterfaceRole, error) {
		calls++
		if calls == 1 {
			return rsdInterfaceUnrelated, nil
		}
		return rsdInterfaceRemoted, nil
	}

	role, err := retryDarwinInterfaceRole(context.Background(), "en43", 0, lookup)
	require.NoError(t, err)
	assert.Equal(t, rsdInterfaceRemoted, role)
	assert.Equal(t, 2, calls)
}

func TestDarwinInterfaceRoleCacheCachesNegativeLookups(t *testing.T) {
	scanCalls := 0
	cache := darwinInterfaceRoleCache{
		expiresAt: time.Now().Add(time.Minute),
		roles:     map[string]rsdInterfaceRole{"en43": rsdInterfaceRemoted},
		scan: func(context.Context) (map[string]rsdInterfaceRole, error) {
			scanCalls++
			return nil, nil
		},
	}

	role, err := cache.role(context.Background(), "en0")
	require.NoError(t, err)
	assert.Equal(t, rsdInterfaceUnrelated, role)
	assert.Zero(t, scanCalls)
}
