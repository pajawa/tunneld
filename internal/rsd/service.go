package rsd

import (
	"context"
	"sync"

	"github.com/dmdmdm-nz/tunneld/internal/netmon"
	"github.com/dmdmdm-nz/tunneld/internal/runtime"
	log "github.com/sirupsen/logrus"
)

// discoveryInfo tracks an active discovery for an interface
type discoveryInfo struct {
	id     uint64
	cancel context.CancelFunc
}

type rsdInterfaceRole uint8

const (
	rsdInterfaceUnknown rsdInterfaceRole = iota
	rsdInterfacePublic
	rsdInterfaceRemoted
	rsdInterfaceUnrelated
)

type Service struct {
	// NetMon subscription
	ifCh    <-chan netmon.InterfaceEvent
	ifUnsub func()

	// State: RSD endpoints by key; also track which interface they came from.
	mu     sync.RWMutex
	rsdMap map[string]RsdService

	// Fan-out to RSD subscribers
	subsMu sync.Mutex
	subs   map[int]*runtime.SubQueue[RsdServiceEvent]
	nextID int

	// Discovery tracking: one discovery per interface, cancellable
	discoveriesMu   sync.Mutex
	discoveries     map[string]discoveryInfo // interface name -> discovery info
	nextDiscoveryID uint64
	wg              sync.WaitGroup // Track goroutines for clean shutdown
	interfaceRole   func(context.Context, string) (rsdInterfaceRole, error)
	findRsdService  func(context.Context, string) (RsdService, error)

	closed bool
}

func NewService() *Service {
	return &Service{
		rsdMap:         make(map[string]RsdService),
		subs:           make(map[int]*runtime.SubQueue[RsdServiceEvent]),
		discoveries:    make(map[string]discoveryInfo),
		interfaceRole:  platformRsdInterfaceRole,
		findRsdService: FindRsdService,
	}
}

// AttachNetmon wires the Netmon stream (must be called before Start).
func (s *Service) AttachNetmon(ch <-chan netmon.InterfaceEvent, unsub func()) {
	s.ifCh = ch
	s.ifUnsub = unsub
}

// Subscribe follows the same "snapshot as Adds, then live" pattern.
func (s *Service) Subscribe() (<-chan RsdServiceEvent, func()) {
	// Snapshot
	s.mu.RLock()
	snapshot := make([]RsdServiceEvent, 0, len(s.rsdMap))
	for _, info := range s.rsdMap {
		snapshot = append(snapshot, RsdServiceEvent{
			Type: RsdServiceAdded,
			Info: info,
		})
	}
	s.mu.RUnlock()

	outBuf := len(snapshot) + 8
	sub := runtime.NewSubQueue[RsdServiceEvent](outBuf)

	// Register paused
	s.subsMu.Lock()
	id := s.nextID
	s.nextID++
	s.subs[id] = sub
	s.subsMu.Unlock()

	// Emit snapshot as RSDAdded
	for _, event := range snapshot {
		sub.OutOfBandSnapshotSend(RsdServiceEvent{
			Type: event.Type,
			Info: event.Info,
		})
	}

	// Go live
	sub.SetPaused(false)

	unsub := func() {
		s.subsMu.Lock()
		if q, ok := s.subs[id]; ok {
			delete(s.subs, id)
			q.Close()
		}
		s.subsMu.Unlock()
	}
	return sub.Chan(), unsub
}

func (s *Service) Start(ctx context.Context) error {
	log.Info("Starting RSD monitoring service")
	defer log.Info("Stopping RSD monitoring service")
	if s.ifCh == nil {
		log.Error("AttachNetmon was not called before Start")
		<-ctx.Done()
		return nil
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case ev, ok := <-s.ifCh:
			if !ok {
				return nil
			}
			s.handleNetworkInterfaceEvent(ctx, ev)
		}
	}
}

func (s *Service) Close() error {
	if s.ifUnsub != nil {
		s.ifUnsub()
	}

	// Cancel all in-progress discoveries
	s.discoveriesMu.Lock()
	for _, info := range s.discoveries {
		info.cancel()
	}
	s.discoveries = make(map[string]discoveryInfo)
	s.discoveriesMu.Unlock()

	// Wait for discovery goroutines to finish
	s.wg.Wait()

	s.subsMu.Lock()
	defer s.subsMu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	for id, q := range s.subs {
		q.Close()
		delete(s.subs, id)
	}
	return nil
}

func (s *Service) handleNetworkInterfaceEvent(ctx context.Context, ev netmon.InterfaceEvent) {
	switch ev.Type {
	case netmon.InterfaceAdded:
		// Check if discovery already in progress for this interface
		s.discoveriesMu.Lock()
		if _, exists := s.discoveries[ev.InterfaceName]; exists {
			// Discovery already in progress, skip
			s.discoveriesMu.Unlock()
			log.WithField("interface", ev.InterfaceName).Debug("Discovery already in progress, skipping")
			return
		}

		// Create cancellable context for this discovery with a unique ID
		discoverCtx, cancel := context.WithCancel(ctx)
		s.nextDiscoveryID++
		discoveryID := s.nextDiscoveryID
		s.discoveries[ev.InterfaceName] = discoveryInfo{id: discoveryID, cancel: cancel}
		s.discoveriesMu.Unlock()

		// Track goroutine for clean shutdown
		s.wg.Go(func() {
			defer func() {
				s.discoveriesMu.Lock()
				// Only delete if this is still our discovery (not replaced by a newer one)
				if info, exists := s.discoveries[ev.InterfaceName]; exists && info.id == discoveryID {
					delete(s.discoveries, ev.InterfaceName)
				}
				s.discoveriesMu.Unlock()
			}()

			role, err := s.interfaceRole(discoverCtx, ev.InterfaceName)
			if err != nil {
				if discoverCtx.Err() != nil {
					return
				}
				role = rsdInterfaceUnknown
				log.WithField("interface", ev.InterfaceName).WithError(err).
					Warn("Could not classify interface, attempting RSD discovery")
			}
			if role == rsdInterfacePublic || role == rsdInterfaceUnrelated {
				message := "Skipping interface unrelated to RSD"
				if role == rsdInterfacePublic {
					message = "Skipping public CDC-NCM interface"
				}
				log.WithField("interface", ev.InterfaceName).Info(message)
				return
			}

			rsdService, err := s.findRsdService(discoverCtx, ev.InterfaceName)
			if err != nil {
				log.WithField("interface", ev.InterfaceName).WithError(err).Trace("Stopped looking for an RSD service")
				return
			}

			log.WithFields(log.Fields{
				"interface":     ev.InterfaceName,
				"udid":          rsdService.Udid,
				"address":       rsdService.Address,
				"deviceVersion": rsdService.DeviceIosVersion,
			}).Info("Discovered RSD service")

			// Add to map and broadcast Added
			s.mu.Lock()
			s.rsdMap[rsdService.Udid] = rsdService
			s.mu.Unlock()
			s.broadcast(RsdServiceEvent{Type: RsdServiceAdded, Info: rsdService})

			log.WithFields(log.Fields{
				"interface": ev.InterfaceName,
				"udid":      rsdService.Udid,
				"address":   rsdService.Address,
			}).Debug("RSD event processing complete")
		})

	case netmon.InterfaceRemoved:
		// Cancel any in-progress discovery for this interface
		s.discoveriesMu.Lock()
		if info, exists := s.discoveries[ev.InterfaceName]; exists {
			info.cancel()
			delete(s.discoveries, ev.InterfaceName)
		}
		s.discoveriesMu.Unlock()

		// Remove any services associated with this interface
		var removed []RsdService
		s.mu.Lock()
		for k, v := range s.rsdMap {
			if v.InterfaceName == ev.InterfaceName {
				removed = append(removed, v)
				delete(s.rsdMap, k)
			}
		}
		s.mu.Unlock()

		for _, rsdService := range removed {
			log.WithFields(log.Fields{
				"interface": ev.InterfaceName,
				"udid":      rsdService.Udid,
				"address":   rsdService.Address,
			}).Info("Detected missing RSD service")

			s.broadcast(RsdServiceEvent{Type: RsdServiceRemoved, Info: rsdService})
		}
	}
}

func (s *Service) broadcast(ev RsdServiceEvent) {
	s.subsMu.Lock()
	defer s.subsMu.Unlock()
	for _, sub := range s.subs {
		sub.Enqueue(ev)
	}
}
