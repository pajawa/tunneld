//go:build darwin

package rsd

import (
	"context"
	"errors"
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

	snapshot, err := parseDarwinInterfaceRoles(output)
	require.NoError(t, err)

	assert.Equal(t, rsdInterfacePublic, snapshot.roles["en48"])
	assert.Equal(t, rsdInterfaceRemoted, snapshot.roles["en43"])
	assert.NotContains(t, snapshot.roles, "en36")
	assert.Equal(t, rsdInterfaceUnrelated, snapshot.role("en0"))
	assert.Equal(t, rsdInterfaceUnrelated, snapshot.role("en36"))
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

	snapshot, err := parseDarwinInterfaceRoles(output)
	require.NoError(t, err)
	assert.Equal(t, rsdInterfaceUnknown, snapshot.roles["en25"])
	assert.Equal(t, rsdInterfaceUnrelated, snapshot.role("en0"))
	assert.Equal(t, rsdInterfaceUnrelated, snapshot.role("en38"))
	assert.True(t, snapshot.reliableAbsence)
}

func TestParseDarwinInterfaceRolesFailsOpenWithoutHiddenMarker(t *testing.T) {
	output, err := os.ReadFile("testdata/ioreg_iphone.txt")
	require.NoError(t, err)
	output = []byte(strings.ReplaceAll(string(output), `"HiddenInterface" = Yes`, `"HiddenConfiguration" = Yes`))

	snapshot, err := parseDarwinInterfaceRoles(output)
	require.NoError(t, err)
	assert.Equal(t, rsdInterfaceUnknown, snapshot.roles["en48"])
	assert.Equal(t, rsdInterfaceUnknown, snapshot.roles["en43"])
}

func TestParseDarwinInterfaceRolesNormalizesPropertyValues(t *testing.T) {
	output, err := os.ReadFile("testdata/ioreg_iphone.txt")
	require.NoError(t, err)
	output = []byte(strings.ReplaceAll(string(output), `"BSD Name" = "en48"`, `"BSD Name" = en48`))
	output = []byte(strings.ReplaceAll(string(output), `"HiddenInterface" = Yes`, `"HiddenInterface" = "Yes"`))

	snapshot, err := parseDarwinInterfaceRoles(output)
	require.NoError(t, err)
	assert.Equal(t, rsdInterfacePublic, snapshot.roles["en48"])
	assert.Equal(t, rsdInterfaceRemoted, snapshot.roles["en43"])
}

func TestParseDarwinInterfaceRolesNormalizesNumericValues(t *testing.T) {
	output, err := os.ReadFile("testdata/ioreg_iphone.txt")
	require.NoError(t, err)
	output = []byte(strings.ReplaceAll(string(output), `"idVendor" = 1452`, `"idVendor" = "1452"`))

	snapshot, err := parseDarwinInterfaceRoles(output)
	require.NoError(t, err)
	assert.Equal(t, rsdInterfacePublic, snapshot.roles["en48"])
	assert.Equal(t, rsdInterfaceRemoted, snapshot.roles["en43"])
}

func TestParseDarwinInterfaceRolesFailsOpenWhenVendorIsMissing(t *testing.T) {
	output, err := os.ReadFile("testdata/ioreg_iphone.txt")
	require.NoError(t, err)
	output = []byte(strings.ReplaceAll(string(output), `"idVendor" = 1452`, `"USB Vendor" = 1452`))

	snapshot, err := parseDarwinInterfaceRoles(output)
	require.NoError(t, err)
	assert.False(t, snapshot.reliableAbsence)
	assert.Equal(t, rsdInterfaceUnknown, snapshot.role("en48"))
	assert.Equal(t, rsdInterfaceUnknown, snapshot.role("en43"))
}

func TestParseDarwinInterfaceRolesMarksIncompleteAppleNCMTreeUnreliable(t *testing.T) {
	output, err := os.ReadFile("testdata/ioreg_iphone.txt")
	require.NoError(t, err)
	output = []byte(strings.ReplaceAll(string(output), `"BSD Name"`, `"Interface Name"`))

	snapshot, err := parseDarwinInterfaceRoles(output)
	require.NoError(t, err)
	assert.False(t, snapshot.reliableAbsence)
	assert.Equal(t, rsdInterfaceUnknown, snapshot.role("en43"))
}

func TestParseDarwinInterfaceRolesRejectsMalformedSnapshot(t *testing.T) {
	_, err := parseDarwinInterfaceRoles([]byte(`"idVendor" = 1452`))
	require.ErrorContains(t, err, "no IOUSBHostDevice nodes found")
}

func TestParseIORegNodesIgnoresNodeMarkerInsideProperty(t *testing.T) {
	nodes := parseIORegNodes([]byte(`
+-o Device  <class IOUSBHostDevice, id 0x1>
  | {
  |   "Product Name" = "contains +-o <class Bogus, data>"
  |   "idVendor" = 1452
  | }
`))
	require.Len(t, nodes, 1)
	vendor, ok := nodeInt(nodes[0], "idVendor")
	require.True(t, ok)
	assert.Equal(t, appleVendorID, vendor)
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

func TestDescendantPropertiesStayWithinUSBDeviceBoundary(t *testing.T) {
	root := &ioregNode{
		children: []*ioregNode{
			{class: "IOEthernetInterface", properties: map[string]string{"BSD Name": `"en43"`}},
			{class: "IOBlockStorageDevice", properties: map[string]string{"BSD Name": `"disk4"`}},
			{
				class:      "IOUSBHostDevice",
				properties: map[string]string{"HiddenInterface": "Yes"},
				children: []*ioregNode{
					{class: "IOEthernetInterface", properties: map[string]string{"BSD Name": `"en99"`}},
				},
			},
		},
	}

	assert.Equal(t, []string{"en43"}, descendantBSDNames(root))
	assert.False(t, descendantHasProperty(root, "HiddenInterface", "Yes"))
}

func TestRetryDarwinInterfaceRoleRetriesUncertainResults(t *testing.T) {
	tests := map[string]struct {
		role rsdInterfaceRole
		err  error
	}{
		"unrelated": {role: rsdInterfaceUnrelated},
		"unknown":   {role: rsdInterfaceUnknown},
		"error":     {role: rsdInterfaceUnknown, err: errors.New("partial snapshot")},
	}

	for name, first := range tests {
		t.Run(name, func(t *testing.T) {
			calls := 0
			lookup := func(context.Context, string) (rsdInterfaceRole, error) {
				calls++
				if calls == 1 {
					return first.role, first.err
				}
				return rsdInterfaceRemoted, nil
			}

			role, err := retryDarwinInterfaceRole(context.Background(), "en43", 0, lookup)
			require.NoError(t, err)
			assert.Equal(t, rsdInterfaceRemoted, role)
			assert.Equal(t, 2, calls)
		})
	}
}

func TestDarwinInterfaceRoleCacheCachesNegativeLookups(t *testing.T) {
	scanCalls := 0
	cache := darwinInterfaceRoleCache{
		expiresAt: time.Now().Add(time.Minute),
		snapshot: darwinInterfaceRoleSnapshot{
			roles:           map[string]rsdInterfaceRole{"en43": rsdInterfaceRemoted},
			reliableAbsence: true,
		},
		scan: func(context.Context) (darwinInterfaceRoleSnapshot, error) {
			scanCalls++
			return darwinInterfaceRoleSnapshot{}, nil
		},
	}

	role, err := cache.role(context.Background(), "en0")
	require.NoError(t, err)
	assert.Equal(t, rsdInterfaceUnrelated, role)
	assert.Zero(t, scanCalls)
}

func TestDarwinInterfaceRoleCacheCachesScanFailure(t *testing.T) {
	scanCalls := 0
	cache := darwinInterfaceRoleCache{
		scan: func(context.Context) (darwinInterfaceRoleSnapshot, error) {
			scanCalls++
			return darwinInterfaceRoleSnapshot{}, errors.New("ioreg failed")
		},
	}

	for range 2 {
		role, err := cache.role(context.Background(), "en43")
		require.Error(t, err)
		assert.Equal(t, rsdInterfaceUnknown, role)
	}
	assert.Equal(t, 1, scanCalls)
}

func TestDarwinInterfaceRoleCacheDoesNotPublishCancelledScan(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	original := darwinInterfaceRoleSnapshot{
		roles:           map[string]rsdInterfaceRole{"en43": rsdInterfaceRemoted},
		reliableAbsence: true,
	}
	cache := darwinInterfaceRoleCache{
		snapshot: original,
		scan: func(context.Context) (darwinInterfaceRoleSnapshot, error) {
			cancel()
			return darwinInterfaceRoleSnapshot{}, ctx.Err()
		},
	}

	role, err := cache.role(ctx, "en43")
	require.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, rsdInterfaceUnknown, role)
	assert.Equal(t, original, cache.snapshot)
	assert.NoError(t, cache.err)
}
