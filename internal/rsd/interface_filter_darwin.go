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
	ioregCommandTimeout = 2 * time.Second
)

var defaultDarwinInterfaceRoles darwinInterfaceRoleCache

type darwinInterfaceRoleCache struct {
	mu        sync.Mutex
	expiresAt time.Time
	roles     map[string]rsdInterfaceRole
}

type ioregNode struct {
	class      string
	column     int
	properties map[string]string
	children   []*ioregNode
}

func platformRsdInterfaceRole(ctx context.Context, interfaceName string) (rsdInterfaceRole, error) {
	return defaultDarwinInterfaceRoles.role(ctx, interfaceName)
}

func (c *darwinInterfaceRoleCache) role(ctx context.Context, interfaceName string) (rsdInterfaceRole, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if time.Now().Before(c.expiresAt) {
		if role, ok := c.roles[interfaceName]; ok {
			return role, nil
		}
	}

	roles, err := scanDarwinInterfaceRoles(ctx)
	if err != nil {
		return rsdInterfaceUnknown, err
	}
	c.roles = roles
	c.expiresAt = time.Now().Add(ioregCacheDuration)

	role := darwinInterfaceRole(roles, interfaceName)
	c.roles[interfaceName] = role
	return role, nil
}

func scanDarwinInterfaceRoles(ctx context.Context) (map[string]rsdInterfaceRole, error) {
	commandCtx, cancel := context.WithTimeout(ctx, ioregCommandTimeout)
	defer cancel()

	output, err := exec.CommandContext(
		commandCtx,
		"/usr/sbin/ioreg",
		"-r",
		"-c", "IOUSBHostDevice",
		"-l",
		"-w", "0",
		"-d", "4",
	).Output()
	if err != nil {
		return nil, fmt.Errorf("read USB registry: %w", err)
	}

	return parseDarwinInterfaceRoles(output), nil
}

func parseDarwinInterfaceRoles(output []byte) map[string]rsdInterfaceRole {
	roles := make(map[string]rsdInterfaceRole)
	for _, device := range parseIORegNodes(output) {
		if device.class != "IOUSBHostDevice" || nodeInt(device, "idVendor") != appleVendorID {
			continue
		}

		controls := make(map[int]struct{})
		dataInterfaces := make(map[int][]*ioregNode)
		for _, child := range device.children {
			if child.class != "IOUSBHostInterface" {
				continue
			}

			number := nodeInt(child, "bInterfaceNumber")
			switch {
			case nodeInt(child, "bInterfaceClass") == 2 && nodeInt(child, "bInterfaceSubClass") == 0x0d:
				controls[number] = struct{}{}
			case nodeInt(child, "bInterfaceClass") == 10:
				dataInterfaces[number] = append(dataInterfaces[number], child)
			}
		}

		validDataInterfaces := make(map[int][]*ioregNode)
		remotedInterfaceNumber := -1
		for number, nodes := range dataInterfaces {
			for _, node := range nodes {
				for _, name := range descendantBSDNames(node) {
					roles[name] = rsdInterfaceUnknown
				}
			}
			if _, ok := controls[number-1]; !ok {
				continue
			}
			validDataInterfaces[number] = nodes
			if number > remotedInterfaceNumber {
				remotedInterfaceNumber = number
			}
		}

		// Apple devices expose a lower public/data NCM function and a higher
		// private/remoted NCM function. With fewer than two complete pairs,
		// there is not enough information to classify the interface safely.
		if len(validDataInterfaces) < 2 {
			continue
		}

		for number, nodes := range validDataInterfaces {
			role := rsdInterfacePublic
			if number == remotedInterfaceNumber {
				role = rsdInterfaceRemoted
			}
			for _, node := range nodes {
				for _, name := range descendantBSDNames(node) {
					if existing, ok := roles[name]; ok && existing != rsdInterfaceUnknown && existing != role {
						roles[name] = rsdInterfaceUnknown
						continue
					}
					roles[name] = role
				}
			}
		}
	}
	return roles
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
	if value, ok := node.properties["BSD Name"]; ok {
		if name, err := strconv.Unquote(value); err == nil && name != "" {
			names = append(names, name)
		}
	}
	for _, child := range node.children {
		names = append(names, descendantBSDNames(child)...)
	}
	return names
}
