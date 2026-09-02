package rsd

import (
	"context"
	"testing"
	"time"

	"github.com/dmdmdm-nz/tunneld/internal/netmon"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestService_NewService(t *testing.T) {
	s := NewService()
	assert.NotNil(t, s)
	assert.NotNil(t, s.rsdMap)
	assert.NotNil(t, s.subs)
	assert.NotNil(t, s.discoveries)
	assert.NotNil(t, s.interfaceRole)
}

func TestService_AttachNetmon(t *testing.T) {
	s := NewService()

	ch := make(chan netmon.InterfaceEvent)
	called := false
	unsub := func() { called = true }

	s.AttachNetmon(ch, unsub)

	assert.Equal(t, (<-chan netmon.InterfaceEvent)(ch), s.ifCh)

	// Call the stored unsub function
	s.ifUnsub()
	assert.True(t, called)
}

func TestService_Subscribe_EmptySnapshot(t *testing.T) {
	s := NewService()
	defer s.Close()

	ch, unsub := s.Subscribe()
	defer unsub()

	// With no services, should not receive anything immediately
	select {
	case ev := <-ch:
		t.Fatalf("unexpected event from empty service: %+v", ev)
	case <-time.After(100 * time.Millisecond):
		// Expected: no events
	}
}

func TestService_Subscribe_Unsubscribe(t *testing.T) {
	s := NewService()
	defer s.Close()

	ch, unsub := s.Subscribe()

	// Unsubscribe
	unsub()

	// Channel should be closed
	select {
	case _, ok := <-ch:
		assert.False(t, ok, "channel should be closed")
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for channel close")
	}
}

func TestService_Subscribe_ReceivesSnapshot(t *testing.T) {
	s := NewService()
	defer s.Close()

	// Manually add some services to the map
	s.mu.Lock()
	s.rsdMap["udid1"] = RsdService{Udid: "udid1", InterfaceName: "en0", Address: "addr1"}
	s.rsdMap["udid2"] = RsdService{Udid: "udid2", InterfaceName: "en1", Address: "addr2"}
	s.mu.Unlock()

	// Subscribe - should receive snapshot
	ch, unsub := s.Subscribe()
	defer unsub()

	received := make(map[string]RsdServiceEvent)
	for i := 0; i < 2; i++ {
		select {
		case ev := <-ch:
			assert.Equal(t, RsdServiceAdded, ev.Type)
			received[ev.Info.Udid] = ev
		case <-time.After(time.Second):
			t.Fatalf("timeout waiting for snapshot event %d", i)
		}
	}

	assert.Contains(t, received, "udid1")
	assert.Contains(t, received, "udid2")
}

func TestService_MultipleSubscribers(t *testing.T) {
	s := NewService()
	defer s.Close()

	ch1, unsub1 := s.Subscribe()
	defer unsub1()
	ch2, unsub2 := s.Subscribe()
	defer unsub2()

	// Broadcast an event
	s.broadcast(RsdServiceEvent{
		Type: RsdServiceAdded,
		Info: RsdService{Udid: "test-udid"},
	})

	// Both should receive the event
	for _, ch := range []<-chan RsdServiceEvent{ch1, ch2} {
		select {
		case ev := <-ch:
			assert.Equal(t, RsdServiceAdded, ev.Type)
			assert.Equal(t, "test-udid", ev.Info.Udid)
		case <-time.After(time.Second):
			t.Fatal("timeout waiting for event")
		}
	}
}

func TestService_HandleNetworkInterfaceEvent_Remove(t *testing.T) {
	s := NewService()
	defer s.Close()

	// Add a service first
	s.mu.Lock()
	s.rsdMap["udid1"] = RsdService{Udid: "udid1", InterfaceName: "en0", Address: "addr1"}
	s.rsdMap["udid2"] = RsdService{Udid: "udid2", InterfaceName: "en1", Address: "addr2"}
	s.mu.Unlock()

	ch, unsub := s.Subscribe()
	defer unsub()

	// Drain snapshot
	for i := 0; i < 2; i++ {
		<-ch
	}

	// Send interface removed event
	ctx := context.Background()
	s.handleNetworkInterfaceEvent(ctx, netmon.InterfaceEvent{
		Type:          netmon.InterfaceRemoved,
		InterfaceName: "en0",
	})

	// Should receive service removed event for udid1 only
	select {
	case ev := <-ch:
		assert.Equal(t, RsdServiceRemoved, ev.Type)
		assert.Equal(t, "udid1", ev.Info.Udid)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for service removed event")
	}

	// Should not receive event for udid2
	select {
	case ev := <-ch:
		t.Fatalf("unexpected event: %+v", ev)
	case <-time.After(100 * time.Millisecond):
		// Expected
	}

	// Verify udid1 was removed from map
	s.mu.RLock()
	_, exists := s.rsdMap["udid1"]
	s.mu.RUnlock()
	assert.False(t, exists, "udid1 should be removed from map")

	// Verify udid2 still exists
	s.mu.RLock()
	_, exists = s.rsdMap["udid2"]
	s.mu.RUnlock()
	assert.True(t, exists, "udid2 should still exist in map")
}

func TestService_HandleNetworkInterfaceEvent_RemoveMultiple(t *testing.T) {
	s := NewService()
	defer s.Close()

	// Add multiple services on same interface
	s.mu.Lock()
	s.rsdMap["udid1"] = RsdService{Udid: "udid1", InterfaceName: "en0", Address: "addr1"}
	s.rsdMap["udid2"] = RsdService{Udid: "udid2", InterfaceName: "en0", Address: "addr2"}
	s.mu.Unlock()

	ch, unsub := s.Subscribe()
	defer unsub()

	// Drain snapshot
	for i := 0; i < 2; i++ {
		<-ch
	}

	// Send interface removed event
	ctx := context.Background()
	s.handleNetworkInterfaceEvent(ctx, netmon.InterfaceEvent{
		Type:          netmon.InterfaceRemoved,
		InterfaceName: "en0",
	})

	// Should receive both removed events
	received := make(map[string]bool)
	for i := 0; i < 2; i++ {
		select {
		case ev := <-ch:
			assert.Equal(t, RsdServiceRemoved, ev.Type)
			received[ev.Info.Udid] = true
		case <-time.After(time.Second):
			t.Fatalf("timeout waiting for service removed event %d", i)
		}
	}

	assert.True(t, received["udid1"])
	assert.True(t, received["udid2"])

	// Map should be empty
	s.mu.RLock()
	assert.Empty(t, s.rsdMap)
	s.mu.RUnlock()
}

func TestService_Close(t *testing.T) {
	s := NewService()

	// Set up netmon unsub
	unsubCalled := false
	s.ifUnsub = func() { unsubCalled = true }

	ch, _ := s.Subscribe() // Don't call unsub, let Close handle it

	err := s.Close()
	require.NoError(t, err)

	// Netmon unsub should be called
	assert.True(t, unsubCalled)

	// Channel should be closed
	select {
	case _, ok := <-ch:
		assert.False(t, ok, "channel should be closed after service close")
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for channel close")
	}
}

func TestService_Close_Idempotent(t *testing.T) {
	s := NewService()
	s.ifUnsub = func() {} // Prevent nil pointer

	// Close twice should not panic
	require.NotPanics(t, func() {
		_ = s.Close()
		_ = s.Close()
	})
}

func TestService_Close_NilUnsub(t *testing.T) {
	s := NewService()
	// ifUnsub is nil

	// Should not panic
	require.NotPanics(t, func() {
		_ = s.Close()
	})
}

func TestService_Start_WithoutAttachNetmon(t *testing.T) {
	s := NewService()
	defer s.Close()

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- s.Start(ctx)
	}()

	// Give it time to start and log error
	time.Sleep(50 * time.Millisecond)

	cancel()

	select {
	case err := <-done:
		assert.NoError(t, err) // Returns nil even without AttachNetmon
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for Start to return")
	}
}

func TestService_Start_ContextCancellation(t *testing.T) {
	s := NewService()
	defer s.Close()

	// Attach mock netmon channel
	ifCh := make(chan netmon.InterfaceEvent)
	s.AttachNetmon(ifCh, func() {})

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- s.Start(ctx)
	}()

	// Give it time to start
	time.Sleep(50 * time.Millisecond)

	cancel()

	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for Start to return")
	}
}

func TestService_Start_ChannelClose(t *testing.T) {
	s := NewService()
	defer s.Close()

	// Attach mock netmon channel
	ifCh := make(chan netmon.InterfaceEvent)
	s.AttachNetmon(ifCh, func() {})

	ctx := context.Background()

	done := make(chan error, 1)
	go func() {
		done <- s.Start(ctx)
	}()

	// Give it time to start
	time.Sleep(50 * time.Millisecond)

	// Close the netmon channel
	close(ifCh)

	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for Start to return")
	}
}

func TestService_HandleInterfaceAdded_SkipsDuplicateDiscovery(t *testing.T) {
	s := NewService()
	defer s.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Simulate a discovery already in progress
	s.discoveriesMu.Lock()
	s.discoveries["en0"] = discoveryInfo{id: 1, cancel: func() {}}
	s.discoveriesMu.Unlock()

	// Send InterfaceAdded event for same interface
	s.handleNetworkInterfaceEvent(ctx, netmon.InterfaceEvent{
		Type:          netmon.InterfaceAdded,
		InterfaceName: "en0",
	})

	// Should still only have one entry (the original one)
	s.discoveriesMu.Lock()
	count := len(s.discoveries)
	s.discoveriesMu.Unlock()

	assert.Equal(t, 1, count, "should not spawn duplicate discovery")
}

func TestService_HandleInterfaceAdded_SkipsIneligibleInterfaces(t *testing.T) {
	for name, role := range map[string]rsdInterfaceRole{
		"public CDC-NCM": rsdInterfacePublic,
		"ordinary en":    rsdInterfaceUnrelated,
	} {
		t.Run(name, func(t *testing.T) {
			s := NewService()
			s.interfaceRole = func(context.Context, string) (rsdInterfaceRole, error) {
				return role, nil
			}

			s.handleNetworkInterfaceEvent(context.Background(), netmon.InterfaceEvent{
				Type:          netmon.InterfaceAdded,
				InterfaceName: "en25",
			})
			s.wg.Wait()

			s.discoveriesMu.Lock()
			defer s.discoveriesMu.Unlock()
			assert.Empty(t, s.discoveries)
		})
	}
}

func TestService_HandleInterfaceRemoved_CancelsDiscovery(t *testing.T) {
	s := NewService()
	defer s.Close()

	ctx := context.Background()

	// Track if cancel was called
	cancelCalled := false
	s.discoveriesMu.Lock()
	s.discoveries["en0"] = discoveryInfo{id: 1, cancel: func() { cancelCalled = true }}
	s.discoveriesMu.Unlock()

	// Send InterfaceRemoved event
	s.handleNetworkInterfaceEvent(ctx, netmon.InterfaceEvent{
		Type:          netmon.InterfaceRemoved,
		InterfaceName: "en0",
	})

	// Cancel should have been called
	assert.True(t, cancelCalled, "cancel should be called when interface is removed")

	// Discovery should be removed from map
	s.discoveriesMu.Lock()
	_, exists := s.discoveries["en0"]
	s.discoveriesMu.Unlock()
	assert.False(t, exists, "discovery should be removed from map")
}

func TestService_Close_CancelsAllDiscoveries(t *testing.T) {
	s := NewService()

	// Track if cancels were called
	cancel1Called := false
	cancel2Called := false

	s.discoveriesMu.Lock()
	s.discoveries["en0"] = discoveryInfo{id: 1, cancel: func() { cancel1Called = true }}
	s.discoveries["en1"] = discoveryInfo{id: 2, cancel: func() { cancel2Called = true }}
	s.discoveriesMu.Unlock()

	err := s.Close()
	require.NoError(t, err)

	// Both cancels should have been called
	assert.True(t, cancel1Called, "cancel1 should be called on Close")
	assert.True(t, cancel2Called, "cancel2 should be called on Close")

	// Discoveries map should be reset
	s.discoveriesMu.Lock()
	count := len(s.discoveries)
	s.discoveriesMu.Unlock()
	assert.Equal(t, 0, count, "discoveries map should be empty after Close")
}

func TestService_DiscoveryID_PreventsWrongDeletion(t *testing.T) {
	// This tests that an old goroutine's defer doesn't delete a newer discovery
	s := NewService()
	defer s.Close()

	// Simulate: old discovery with ID=1 was cancelled, new discovery with ID=2 started
	s.discoveriesMu.Lock()
	s.discoveries["en0"] = discoveryInfo{id: 2, cancel: func() {}}
	s.discoveriesMu.Unlock()

	// Simulate old goroutine trying to clean up with ID=1
	// (This is what the defer does, checking if the ID matches)
	s.discoveriesMu.Lock()
	oldDiscoveryID := uint64(1)
	if info, exists := s.discoveries["en0"]; exists && info.id == oldDiscoveryID {
		// This should NOT execute because IDs don't match
		delete(s.discoveries, "en0")
	}
	s.discoveriesMu.Unlock()

	// The new discovery (ID=2) should still be in the map
	s.discoveriesMu.Lock()
	info, exists := s.discoveries["en0"]
	s.discoveriesMu.Unlock()

	assert.True(t, exists, "new discovery should still exist")
	assert.Equal(t, uint64(2), info.id, "discovery ID should be 2")
}
