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
	ioregFailureCache   = 100 * time.Millisecond
	ioregNegativeRetry  = 750 * time.Millisecond
	ioregCommandTimeout = 2 * time.Second
)

var defaultDarwinInterfaceRoles darwinInterfaceRoleCache

type darwinInterfaceRoleCache struct {
	mu        sync.Mutex
	expiresAt time.Time
	snapshot  darwinInterfaceRoleSnapshot
	err       error
	scan      func(context.Context) (darwinInterfaceRoleSnapshot, error)
}

type darwinInterfaceRoleSnapshot struct {
	roles           map[string]rsdInterfaceRole
	reliableAbsence bool
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
	if err == nil && role != rsdInterfaceUnknown && role != rsdInterfaceUnrelated {
		return role, err
	}
	if ctx.Err() != nil {
		return rsdInterfaceUnknown, ctx.Err()
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
		return c.snapshot.role(interfaceName), c.err
	}
	if err := ctx.Err(); err != nil {
		return rsdInterfaceUnknown, err
	}

	scan := c.scan
	if scan == nil {
		scan = scanDarwinInterfaceRoles
	}
	snapshot, err := scan(ctx)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return rsdInterfaceUnknown, ctxErr
		}
		c.snapshot = snapshot
		c.err = err
		c.expiresAt = time.Now().Add(ioregFailureCache)
		return rsdInterfaceUnknown, err
	}
	c.snapshot = snapshot
	c.err = nil
	c.expiresAt = time.Now().Add(ioregCacheDuration)

	return snapshot.role(interfaceName), nil
}

func scanDarwinInterfaceRoles(ctx context.Context) (darwinInterfaceRoleSnapshot, error) {
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
			return darwinInterfaceRoleSnapshot{}, fmt.Errorf("read USB registry: %w", commandCtx.Err())
		}
		if detail := strings.TrimSpace(stderr.String()); detail != "" {
			return darwinInterfaceRoleSnapshot{}, fmt.Errorf("read USB registry: %w: %s", err, detail)
		}
		return darwinInterfaceRoleSnapshot{}, fmt.Errorf("read USB registry: %w", err)
	}

	snapshot, err := parseDarwinInterfaceRoles(output)
	if err != nil {
		return darwinInterfaceRoleSnapshot{}, fmt.Errorf("parse USB registry: %w", err)
	}
	return snapshot, nil
}

func parseDarwinInterfaceRoles(output []byte) (darwinInterfaceRoleSnapshot, error) {
	snapshot := darwinInterfaceRoleSnapshot{
		roles:           make(map[string]rsdInterfaceRole),
		reliableAbsence: true,
	}
	deviceCount := 0
	for _, device := range parseIORegNodes(output) {
		if device.class != "IOUSBHostDevice" {
			continue
		}
		deviceCount++

		interfaces := descendantUSBHostInterfaces(device)
		vendor, vendorOK := nodeInt(device, "idVendor")
		if vendorOK && vendor != appleVendorID {
			continue
		}

		controls := make(map[int]struct{})
		dataInterfaces := make(map[int][]*ioregNode)
		deviceNames := make(map[string]struct{})
		for _, child := range interfaces {
			for _, name := range descendantBSDNames(child) {
				deviceNames[name] = struct{}{}
			}

			number, numberOK := nodeInt(child, "bInterfaceNumber")
			class, classOK := nodeInt(child, "bInterfaceClass")
			subclass, subclassOK := nodeInt(child, "bInterfaceSubClass")
			switch {
			case numberOK && classOK && subclassOK && class == 2 && subclass == 0x0d:
				controls[number] = struct{}{}
			case numberOK && classOK && class == 10:
				dataInterfaces[number] = append(dataInterfaces[number], child)
			}
		}

		deviceRoles := make(map[string]rsdInterfaceRole, len(deviceNames))
		for name := range deviceNames {
			deviceRoles[name] = rsdInterfaceUnknown
		}
		if !vendorOK {
			snapshot.reliableAbsence = false
			mergeDarwinInterfaceRoles(snapshot.roles, deviceRoles)
			continue
		}
		if len(controls) == 0 && len(dataInterfaces) == 0 {
			continue
		}

		complete := len(controls) == 2 && len(dataInterfaces) == 2
		missingBSDName := false
		for number := range controls {
			if _, ok := dataInterfaces[number+1]; !ok {
				complete = false
			}
		}
		for number, nodes := range dataInterfaces {
			if _, ok := controls[number-1]; !ok {
				complete = false
			}
			for _, node := range nodes {
				if len(descendantBSDNames(node)) == 0 {
					complete = false
					missingBSDName = true
				}
			}
		}
		if missingBSDName {
			snapshot.reliableAbsence = false
		}
		if !complete {
			mergeDarwinInterfaceRoles(snapshot.roles, deviceRoles)
			continue
		}

		hiddenDataInterfaces := make([]int, 0, 1)
		for number, nodes := range dataInterfaces {
			for _, node := range nodes {
				if descendantHasProperty(node, "HiddenInterface", "Yes") {
					hiddenDataInterfaces = append(hiddenDataInterfaces, number)
					break
				}
			}
		}

		// Current Apple devices expose exactly two complete NCM functions. The
		// private/remoted function has a positive HiddenInterface marker and is
		// also the higher-numbered function. Any incomplete or contradictory
		// snapshot remains unknown so RSD discovery fails open.
		if len(dataInterfaces) == 2 && len(hiddenDataInterfaces) == 1 {
			remotedInterfaceNumber := hiddenDataInterfaces[0]
			for number := range dataInterfaces {
				if number > remotedInterfaceNumber {
					remotedInterfaceNumber = -1
					break
				}
			}

			if remotedInterfaceNumber >= 0 {
				for number, nodes := range dataInterfaces {
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

		mergeDarwinInterfaceRoles(snapshot.roles, deviceRoles)
	}

	if deviceCount == 0 {
		return darwinInterfaceRoleSnapshot{}, fmt.Errorf("no IOUSBHostDevice nodes found")
	}
	return snapshot, nil
}

func (s darwinInterfaceRoleSnapshot) role(interfaceName string) rsdInterfaceRole {
	if role, ok := s.roles[interfaceName]; ok {
		return role
	}
	if !s.reliableAbsence {
		return rsdInterfaceUnknown
	}
	return rsdInterfaceUnrelated
}

func mergeDarwinInterfaceRoles(target, source map[string]rsdInterfaceRole) {
	for name, role := range source {
		if existing, ok := target[name]; ok && existing != role {
			target[name] = rsdInterfaceUnknown
			continue
		}
		target[name] = role
	}
}

func parseIORegNodes(output []byte) []*ioregNode {
	var nodes []*ioregNode
	var stack []*ioregNode
	var current *ioregNode

	for _, rawLine := range bytes.Split(output, []byte{'\n'}) {
		line := string(rawLine)
		column := strings.Index(line, "+-o ")
		if column >= 0 && ioregTreePrefix(line[:column]) {
			class := ioregClass(line)
			if class != "" {
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

func ioregTreePrefix(prefix string) bool {
	for _, char := range prefix {
		if char != ' ' && char != '|' {
			return false
		}
	}
	return true
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

func nodeInt(node *ioregNode, key string) (int, bool) {
	value, ok := nodeString(node, key)
	if !ok {
		return 0, false
	}
	parsed, err := strconv.ParseInt(value, 0, 32)
	if err != nil {
		return 0, false
	}
	return int(parsed), true
}

func descendantBSDNames(node *ioregNode) []string {
	var names []string
	if node.class == "IOEthernetInterface" {
		if name, ok := nodeString(node, "BSD Name"); ok && name != "" {
			names = append(names, name)
		}
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
