//go:build darwin

package netmon

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// Routing message types we care about
const (
	rtmNewAddr = 0x0c // RTM_NEWADDR - address added
	rtmDelAddr = 0x0d // RTM_DELADDR - address removed
	rtmIfInfo  = 0x0e // RTM_IFINFO - interface up/down
)

type darwinWatcher struct {
	mu      sync.Mutex
	tracked map[string]struct{}
}

// NewWatcher creates a macOS-specific watcher using AF_ROUTE sockets.
func NewWatcher() Watcher {
	return &darwinWatcher{
		tracked: make(map[string]struct{}),
	}
}

func (w *darwinWatcher) Start(ctx context.Context, callback func(InterfaceEvent)) error {
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return err
	}

	// Close socket when context is cancelled
	go func() {
		<-ctx.Done()
		unix.Close(fd)
	}()

	// Initialize tracked map with current interfaces (only time we scan all)
	w.reconcileAll(callback)
	log.Debug("Darwin watcher initialized")

	buf := make([]byte, 4096)

	for {
		n, err := unix.Read(fd, buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				log.WithError(err).Warn("Error reading from route socket")
				continue
			}
		}

		if n < 14 {
			continue
		}

		// Message header layout for if_msghdr / ifa_msghdr:
		// - bytes 0-1: msglen
		// - byte 2: version
		// - byte 3: type
		// - bytes 4-7: addrs
		// - bytes 8-11: flags
		// - bytes 12-13: interface index
		msgType := buf[3]

		// Only process interface-related messages
		if msgType != rtmIfInfo && msgType != rtmNewAddr && msgType != rtmDelAddr {
			continue
		}

		ifIndex := int(binary.LittleEndian.Uint16(buf[12:14]))
		if ifIndex == 0 {
			continue
		}

		// For RTM_IFINFO, we can extract flags directly from the message
		var ifFlags uint32
		if msgType == rtmIfInfo {
			ifFlags = binary.LittleEndian.Uint32(buf[8:12])
		}

		log.WithFields(log.Fields{
			"msgType": msgType,
			"ifIndex": ifIndex,
			"flags":   ifFlags,
		}).Trace("Received interface event")

		w.handleInterfaceEvent(ifIndex, msgType, ifFlags, callback)
	}
}

func (w *darwinWatcher) handleInterfaceEvent(index int, msgType byte, ifFlags uint32, callback func(InterfaceEvent)) {
	// For RTM_IFINFO, we can check if interface is down without calling net functions
	if msgType == rtmIfInfo {
		// IFF_UP is 0x1 in BSD
		isUp := ifFlags&0x1 != 0
		if !isUp {
			w.removeInterfaceByIndex(index, callback)
			return
		}
	}

	// IPv6 addresses can be removed during normal NCM interface reconfiguration.
	// Only an interface-down event or a failed lookup means the interface is gone.
	if msgType == rtmDelAddr {
		return
	}

	// Only call net.InterfaceByIndex for events on interfaces that might be relevant
	iface, err := net.InterfaceByIndex(index)
	if err != nil {
		// Interface may have been removed
		w.removeInterfaceByIndex(index, callback)
		return
	}

	if !strings.HasPrefix(iface.Name, "en") {
		return
	}

	log.WithFields(log.Fields{
		"interface": iface.Name,
		"msgType":   msgType,
	}).Trace("Processing interface event")

	if iface.Flags&net.FlagUp == 0 {
		w.removeInterface(iface.Name, callback)
		return
	}

	hasIPv6 := hasIPv6Address(iface)

	w.mu.Lock()
	defer w.mu.Unlock()

	_, isTracked := w.tracked[iface.Name]

	if hasIPv6 && !isTracked {
		log.WithField("interface", iface.Name).Trace("Interface now has IPv6 address")
		w.tracked[iface.Name] = struct{}{}
		callback(InterfaceEvent{Type: InterfaceAdded, InterfaceName: iface.Name})
	}
}

func (w *darwinWatcher) removeInterface(name string, callback func(InterfaceEvent)) {
	w.mu.Lock()
	_, isTracked := w.tracked[name]
	delete(w.tracked, name)
	w.mu.Unlock()

	if isTracked {
		log.WithField("interface", name).Trace("Interface removed or down")
		callback(InterfaceEvent{Type: InterfaceRemoved, InterfaceName: name})
	}
}

func (w *darwinWatcher) removeInterfaceByIndex(index int, callback func(InterfaceEvent)) {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Find and remove any tracked interface that no longer exists
	for name := range w.tracked {
		iface, err := net.InterfaceByName(name)
		if err != nil || iface.Index == index {
			log.WithField("interface", name).Trace("Interface removed")
			delete(w.tracked, name)
			callback(InterfaceEvent{Type: InterfaceRemoved, InterfaceName: name})
			return
		}
	}
}

func (w *darwinWatcher) reconcileAll(callback func(InterfaceEvent)) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	for _, iface := range interfaces {
		if !strings.HasPrefix(iface.Name, "en") || iface.Flags&net.FlagUp == 0 {
			continue
		}
		if hasIPv6Address(&iface) {
			log.WithField("interface", iface.Name).Trace("Interface has IPv6 address")
			w.tracked[iface.Name] = struct{}{}
			callback(InterfaceEvent{Type: InterfaceAdded, InterfaceName: iface.Name})
		}
	}
}

func hasIPv6Address(iface *net.Interface) bool {
	addrs, err := iface.Addrs()
	if err != nil {
		return false
	}
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok {
			if ipNet.IP.To4() == nil && ipNet.IP.To16() != nil {
				return true
			}
		}
	}
	return false
}
