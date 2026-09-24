package store_test

import (
	"testing"

	"blueveil/collector/internal/store"
	"blueveil/collector/internal/store/storetest"
)

func TestMemoryBackendConformance(t *testing.T) {
	storetest.Run(t, store.NewMemoryBackend())
}
