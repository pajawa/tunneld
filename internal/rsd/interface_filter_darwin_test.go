//go:build darwin

package rsd

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseDarwinInterfaceRoles(t *testing.T) {
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
  | +-o AppleUSBNCMData  <class AppleUSBNCMData, id 0x4>
  |   +-o en25  <class IOEthernetInterface, id 0x5>
  |       {
  |         "BSD Name" = "en25"
  |       }
  +-o Control@5  <class IOUSBHostInterface, id 0x6>
  | | {
  | |   "bInterfaceClass" = 2
  | |   "bInterfaceSubClass" = 13
  | |   "bInterfaceNumber" = 5
  | | }
  +-o Data@6  <class IOUSBHostInterface, id 0x7>
  | | {
  | |   "bInterfaceClass" = 10
  | |   "bInterfaceNumber" = 6
  | | }
  | +-o AppleUSBNCMData  <class AppleUSBNCMData, id 0x8>
  |   +-o en38  <class IOEthernetInterface, id 0x9>
  |       {
  |         "BSD Name" = "en38"
  |       }

+-o Third-party NCM@00200000  <class IOUSBHostDevice, id 0xa>
  | {
  |   "idVendor" = 3034
  | }
  +-o Control@0  <class IOUSBHostInterface, id 0xb>
  | | {
  | |   "bInterfaceClass" = 2
  | |   "bInterfaceSubClass" = 13
  | |   "bInterfaceNumber" = 0
  | | }
  +-o Data@1  <class IOUSBHostInterface, id 0xc>
  | | {
  | |   "bInterfaceClass" = 10
  | |   "bInterfaceNumber" = 1
  | | }
  | +-o en36  <class IOEthernetInterface, id 0xd>
  |       {
  |         "BSD Name" = "en36"
  |       }
`)

	roles := parseDarwinInterfaceRoles(output)

	assert.Equal(t, rsdInterfacePublic, roles["en25"])
	assert.Equal(t, rsdInterfaceRemoted, roles["en38"])
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

	assert.Equal(t, rsdInterfaceUnknown, parseDarwinInterfaceRoles(output)["en25"])
}
