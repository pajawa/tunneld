//go:build darwin

package netmon

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDarwinWatcherIgnoresDeletedAddress(t *testing.T) {
	const interfaceName = "en-test"

	w := &darwinWatcher{
		tracked: map[string]struct{}{interfaceName: {}},
	}
	var events []InterfaceEvent

	w.handleInterfaceEvent(0, rtmDelAddr, 0, func(event InterfaceEvent) {
		events = append(events, event)
	})

	assert.Empty(t, events)
	assert.Contains(t, w.tracked, interfaceName)
}
