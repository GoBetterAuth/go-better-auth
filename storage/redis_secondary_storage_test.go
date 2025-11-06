package storage

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// setupRedisContainer creates a Redis container for testing and returns cleanup function
func setupRedisContainer(t *testing.T) (*RedisSecondaryStorage, func()) {
	ctx := context.Background()
	req := testcontainers.ContainerRequest{
		Image:        "redis:8.2-alpine",
		ExposedPorts: []string{"6379/tcp"},
		WaitingFor:   wait.ForListeningPort("6379/tcp").WithStartupTimeout(30 * time.Second),
	}
	redisC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err)

	host, err := redisC.Host(ctx)
	require.NoError(t, err)
	port, err := redisC.MappedPort(ctx, "6379")
	require.NoError(t, err)

	portInt, err := strconv.Atoi(port.Port())
	require.NoError(t, err)

	storage, err := NewRedisSecondaryStorage(&RedisConfig{
		Host:       host,
		Port:       portInt,
		DB:         0,
		MaxRetries: 3,
		PoolSize:   10,
	}, nil)
	require.NoError(t, err)

	terminate := func() {
		// Clean up test keys first
		ctx := context.Background()
		if storage.client != nil {
			iter := storage.client.Scan(ctx, 0, "test:*", 0).Iterator()
			for iter.Next(ctx) {
				storage.client.Del(ctx, iter.Val())
			}
		}
		storage.Close()
		redisC.Terminate(ctx)
	}

	return storage, terminate
}

// TestRedisSecondaryStorage_Set tests setting values in Redis storage
func TestRedisSecondaryStorage_Set(t *testing.T) {
	storage, terminate := setupRedisContainer(t)
	defer terminate()

	tests := []struct {
		name      string
		key       string
		value     string
		ttl       int
		expectErr bool
	}{
		{
			name:      "set value without TTL",
			key:       "test:key1",
			value:     "hello",
			ttl:       0,
			expectErr: false,
		},
		{
			name:      "set value with TTL",
			key:       "test:key2",
			value:     "world",
			ttl:       3600,
			expectErr: false,
		},
		{
			name:      "set value with short TTL",
			key:       "test:key3",
			value:     "short-lived",
			ttl:       1,
			expectErr: false,
		},
		{
			name:      "overwrite existing value",
			key:       "test:key4",
			value:     "original",
			ttl:       0,
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			err := storage.Set(ctx, tt.key, tt.value, tt.ttl)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}

	// Cleanup
	storage.Delete(context.Background(), "test:key1")
	storage.Delete(context.Background(), "test:key2")
	storage.Delete(context.Background(), "test:key3")
	storage.Delete(context.Background(), "test:key4")
}

// TestRedisSecondaryStorage_Get tests retrieving values from Redis storage
func TestRedisSecondaryStorage_Get(t *testing.T) {
	storage, terminate := setupRedisContainer(t)
	defer terminate()

	// Set test data
	ctx := context.Background()
	storage.Set(ctx, "test:get1", "test-value", 0)
	defer storage.Delete(ctx, "test:get1")

	tests := []struct {
		name      string
		key       string
		expectVal string
		expectErr bool
	}{
		{
			name:      "get existing value",
			key:       "test:get1",
			expectVal: "test-value",
			expectErr: false,
		},
		{
			name:      "get non-existent key",
			key:       "test:nonexistent",
			expectVal: "",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val, err := storage.Get(ctx, tt.key)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectVal, val)
			}
		})
	}
}

// TestRedisSecondaryStorage_Delete tests deleting values from Redis storage
func TestRedisSecondaryStorage_Delete(t *testing.T) {
	storage, terminate := setupRedisContainer(t)
	defer terminate()

	ctx := context.Background()
	tests := []struct {
		name      string
		key       string
		setup     func()
		expectErr bool
	}{
		{
			name: "delete existing key",
			key:  "test:del1",
			setup: func() {
				storage.Set(ctx, "test:del1", "value", 0)
			},
			expectErr: false,
		},
		{
			name: "delete non-existent key",
			key:  "test:del-nonexistent",
			setup: func() {
				// No setup needed
			},
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setup != nil {
				tt.setup()
			}
			err := storage.Delete(ctx, tt.key)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestRedisSecondaryStorage_TTL tests TTL expiration
func TestRedisSecondaryStorage_TTL(t *testing.T) {
	storage, terminate := setupRedisContainer(t)
	defer terminate()

	ctx := context.Background()
	key := "test:ttl-key"
	value := "short-lived"

	// Set value with 1 second TTL
	err := storage.Set(ctx, key, value, 1)
	require.NoError(t, err)

	// Value should exist immediately
	val, err := storage.Get(ctx, key)
	assert.NoError(t, err)
	assert.Equal(t, value, val)

	// Wait for expiration
	time.Sleep(2 * time.Second)

	// Value should be gone after expiration
	_, err = storage.Get(ctx, key)
	assert.Error(t, err)
}

// TestRedisSecondaryStorage_LargeValues tests storing and retrieving large values
func TestRedisSecondaryStorage_LargeValues(t *testing.T) {
	storage, terminate := setupRedisContainer(t)
	defer terminate()

	ctx := context.Background()
	key := "test:large-key"
	largeValue := ""
	for i := 0; i < 10000; i++ {
		largeValue += "x"
	}

	// Set large value
	err := storage.Set(ctx, key, largeValue, 0)
	require.NoError(t, err)

	// Get large value
	val, err := storage.Get(ctx, key)
	require.NoError(t, err)
	assert.Equal(t, largeValue, val)

	storage.Delete(ctx, key)
}
