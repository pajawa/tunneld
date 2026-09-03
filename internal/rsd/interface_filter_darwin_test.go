//go:build darwin

package rsd

import (
	"os"
	"strings"
	"testing"

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

func TestParseDarwinInterfaceRolesRejectsMalformedSnapshot(t *testing.T) {
	_, err := parseDarwinInterfaceRoles([]byte(`"idVendor" = 1452`))
	require.ErrorContains(t, err, "no IOUSBHostDevice nodes found")
}
