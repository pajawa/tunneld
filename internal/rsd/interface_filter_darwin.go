//go:build darwin

package rsd

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	appleVendorID       = 0x05ac
	ioregCacheDuration  = 500 * time.Millisecond
	ioregNegativeRetry  = 750 * time.Millisecond
	ioregCommandTimeout = 2 * time.Second
)

var defaultDarwinInterfaceRoles darwinInterfaceRoleCache

type darwinInterfaceRoleCache struct {
	mu        sync.Mutex
	expiresAt time.Time
	roles     map[string]rsdInterfaceRole
	scan      func(context.Context) (map[string]rsdInterfaceRole, error)
}

type ioregNode struct {
	class      string
	column     int
	properties map[string]string
	children   []*ioregNode
}

func platformRsdInterfaceRole(ctx context.Context, interfaceName string) (rsdInterfaceRole, error) {
	return retryDarwinInterfaceRole(
		ctx,
		interfaceName,
		ioregNegativeRetry,
		defaultDarwinInterfaceRoles.role,
	)
}

func retryDarwinInterfaceRole(
	ctx context.Context,
	interfaceName string,
	delay time.Duration,
	lookup func(context.Context, string) (rsdInterfaceRole, error),
) (rsdInterfaceRole, error) {
	role, err := lookup(ctx, interfaceName)
	if err != nil || role != rsdInterfaceUnrelated {
		return role, err
	}

	// Netmon emits InterfaceAdded only once. Give a newly published USB
	// interface a second, uncached registry snapshot before deciding it is
	// unrelated, since the BSD node can lag the network event.
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return rsdInterfaceUnknown, ctx.Err()
	case <-timer.C:
		return lookup(ctx, interfaceName)
	}
}

func (c *darwinInterfaceRoleCache) role(ctx context.Context, interfaceName string) (rsdInterfaceRole, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if time.Now().Before(c.expiresAt) {
		return darwinInterfaceRole(c.roles, interfaceName), nil
	}

	scan := c.scan
	if scan == nil {
		scan = scanDarwinInterfaceRoles
	}
	roles, err := scan(ctx)
	if err != nil {
		return rsdInterfaceUnknown, err
	}
	c.roles = roles
	c.expiresAt = time.Now().Add(ioregCacheDuration)

	return darwinInterfaceRole(roles, interfaceName), nil
}

func scanDarwinInterfaceRoles(ctx context.Context) (map[string]rsdInterfaceRole, error) {
	commandCtx, cancel := context.WithTimeout(ctx, ioregCommandTimeout)
	defer cancel()

	command := exec.CommandContext(
		commandCtx,
		"/usr/sbin/ioreg",
		"-r",
		"-c", "IOUSBHostDevice",
		"-l",
		"-w", "0",
	)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	output, err := command.Output()
	if err != nil {
		if commandCtx.Err() != nil {
			return nil, fmt.Errorf("read USB registry: %w", commandCtx.Err())
		}
		if detail := strings.TrimSpace(stderr.String()); detail != "" {
			return nil, fmt.Errorf("read USB registry: %w: %s", err, detail)
		}
		return nil, fmt.Errorf("read USB registry: %w", err)
	}

	roles, err := parseDarwinInterfaceRoles(output)
	if err != nil {
		return nil, fmt.Errorf("parse USB registry: %w", err)
	}
	return roles, nil
}

func parseDarwinInterfaceRoles(output []byte) (map[string]rsdInterfaceRole, error) {
	roles := make(map[string]rsdInterfaceRole)
	deviceCount := 0
	for _, device := range parseIORegNodes(output) {
		if device.class != "IOUSBHostDevice" {
			continue
		}
		deviceCount++
		if nodeInt(device, "idVendor") != appleVendorID {
			continue
		}

		controls := make(map[int]struct{})
		dataInterfaces := make(map[int][]*ioregNode)
		deviceNames := make(map[string]struct{})
		for _, child := range descendantUSBHostInterfaces(device) {
			for _, name := range descendantBSDNames(child) {
				deviceNames[name] = struct{}{}
			}

			number := nodeInt(child, "bInterfaceNumber")
			switch {
			case nodeInt(child, "bInterfaceClass") == 2 && nodeInt(child, "bInterfaceSubClass") == 0x0d:
				controls[number] = struct{}{}
			case nodeInt(child, "bInterfaceClass") == 10:
				dataInterfaces[number] = append(dataInterfaces[number], child)
			}
		}
		for number := range controls {
			if _, ok := dataInterfaces[number+1]; !ok {
				return nil, fmt.Errorf("Apple NCM control %d has no data interface", number)
			}
		}
		for number, nodes := range dataInterfaces {
			if _, ok := controls[number-1]; !ok {
				return nil, fmt.Errorf("Apple NCM data interface %d has no control interface", number)
			}
			for _, node := range nodes {
				if len(descendantBSDNames(node)) == 0 {
					return nil, fmt.Errorf("Apple NCM data interface %d has no BSD name", number)
				}
			}
		}

		validDataInterfaces := make(map[int][]*ioregNode)
		hiddenDataInterfaces := make([]int, 0, 1)
		for number, nodes := range dataInterfaces {
			if _, ok := controls[number-1]; !ok {
				continue
			}
			validDataInterfaces[number] = nodes
			for _, node := range nodes {
				if descendantHasProperty(node, "HiddenInterface", "Yes") {
					hiddenDataInterfaces = append(hiddenDataInterfaces, number)
					break
				}
			}
		}

		deviceRoles := make(map[string]rsdInterfaceRole, len(deviceNames))
		for name := range deviceNames {
			deviceRoles[name] = rsdInterfaceUnknown
		}

		// Current Apple devices expose exactly two complete NCM functions. The
		// private/remoted function has a positive HiddenInterface marker and is
		// also the higher-numbered function. Any incomplete or contradictory
		// snapshot remains unknown so RSD discovery fails open.
		if len(validDataInterfaces) == 2 && len(hiddenDataInterfaces) == 1 {
			remotedInterfaceNumber := hiddenDataInterfaces[0]
			for number := range validDataInterfaces {
				if number > remotedInterfaceNumber {
					remotedInterfaceNumber = -1
					break
				}
			}

			if remotedInterfaceNumber >= 0 {
				for number, nodes := range validDataInterfaces {
					role := rsdInterfacePublic
					if number == remotedInterfaceNumber {
						role = rsdInterfaceRemoted
					}
					for _, node := range nodes {
						for _, name := range descendantBSDNames(node) {
							deviceRoles[name] = role
						}
					}
				}
			}
		}

		for name, role := range deviceRoles {
			if existing, ok := roles[name]; ok && existing != role {
				roles[name] = rsdInterfaceUnknown
				continue
			}
			roles[name] = role
		}
	}

	if deviceCount == 0 {
		return nil, fmt.Errorf("no IOUSBHostDevice nodes found")
	}
	return roles, nil
}

func darwinInterfaceRole(roles map[string]rsdInterfaceRole, interfaceName string) rsdInterfaceRole {
	if role, ok := roles[interfaceName]; ok {
		return role
	}
	// A successful registry snapshot contains every BSD interface backed by
	// an Apple USB NCM function. Anything absent cannot carry remoted traffic.
	return rsdInterfaceUnrelated
}

func parseIORegNodes(output []byte) []*ioregNode {
	var nodes []*ioregNode
	var stack []*ioregNode
	var current *ioregNode

	for _, rawLine := range bytes.Split(output, []byte{'\n'}) {
		line := string(rawLine)
		column := strings.Index(line, "+-o ")
		if column >= 0 {
			class := ioregClass(line)
			if class == "" {
				current = nil
				continue
			}

			node := &ioregNode{
				class:      class,
				column:     column,
				properties: make(map[string]string),
			}
			for len(stack) > 0 && stack[len(stack)-1].column >= column {
				stack = stack[:len(stack)-1]
			}
			if len(stack) > 0 {
				parent := stack[len(stack)-1]
				parent.children = append(parent.children, node)
			}
			stack = append(stack, node)
			nodes = append(nodes, node)
			current = node
			continue
		}

		if current == nil {
			continue
		}
		key, value, ok := ioregProperty(line)
		if ok {
			current.properties[key] = value
		}
	}

	return nodes
}

func ioregClass(line string) string {
	const marker = "<class "
	start := strings.Index(line, marker)
	if start < 0 {
		return ""
	}
	remainder := line[start+len(marker):]
	end := strings.IndexAny(remainder, ",>")
	if end < 0 {
		return ""
	}
	return remainder[:end]
}

func ioregProperty(line string) (string, string, bool) {
	start := strings.IndexByte(line, '"')
	if start < 0 {
		return "", "", false
	}
	remainder := line[start+1:]
	end := strings.IndexByte(remainder, '"')
	if end < 0 {
		return "", "", false
	}
	remainder = strings.TrimSpace(remainder[end+1:])
	if !strings.HasPrefix(remainder, "=") {
		return "", "", false
	}
	return line[start+1 : start+1+end], strings.TrimSpace(remainder[1:]), true
}

func nodeInt(node *ioregNode, key string) int {
	value, ok := node.properties[key]
	if !ok {
		return -1
	}
	parsed, err := strconv.ParseInt(value, 0, 32)
	if err != nil {
		return -1
	}
	return int(parsed)
}

func descendantBSDNames(node *ioregNode) []string {
	var names []string
	if name, ok := nodeString(node, "BSD Name"); ok && name != "" {
		names = append(names, name)
	}
	for _, child := range node.children {
		names = append(names, descendantBSDNames(child)...)
	}
	return names
}

func descendantHasProperty(node *ioregNode, key, value string) bool {
	if actual, ok := nodeString(node, key); ok && strings.EqualFold(actual, value) {
		return true
	}
	for _, child := range node.children {
		if descendantHasProperty(child, key, value) {
			return true
		}
	}
	return false
}

func descendantUSBHostInterfaces(node *ioregNode) []*ioregNode {
	var interfaces []*ioregNode
	for _, child := range node.children {
		if child.class == "IOUSBHostDevice" {
			continue
		}
		if child.class == "IOUSBHostInterface" {
			interfaces = append(interfaces, child)
			continue
		}
		interfaces = append(interfaces, descendantUSBHostInterfaces(child)...)
	}
	return interfaces
}

func nodeString(node *ioregNode, key string) (string, bool) {
	value, ok := node.properties[key]
	if !ok {
		return "", false
	}
	if unquoted, err := strconv.Unquote(value); err == nil {
		return unquoted, true
	}
	return strings.TrimSpace(value), true
}
