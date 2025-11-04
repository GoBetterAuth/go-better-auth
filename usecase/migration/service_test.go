package migration

import (
	"context"
	"log/slog"
	"testing"

	"github.com/GoBetterAuth/go-better-auth/domain"
)

func TestNewService(t *testing.T) {
	config := &domain.Config{
		Database: domain.DatabaseConfig{
			Provider:         "sqlite",
			ConnectionString: ":memory:",
		},
	}

	t.Run("creates service with provided logger", func(t *testing.T) {
		logger := slog.Default()
		service := NewService(config, logger)

		if service == nil {
			t.Fatal("expected service to be created")
		}

		if service.config != config {
			t.Error("expected config to be set")
		}

		if service.logger != logger {
			t.Error("expected logger to be set")
		}
	})

	t.Run("creates service with default logger when nil provided", func(t *testing.T) {
		service := NewService(config, nil)

		if service == nil {
			t.Fatal("expected service to be created")
		}

		if service.logger == nil {
			t.Error("expected default logger to be set")
		}
	})
}

func TestService_createConnection(t *testing.T) {
	t.Run("success with valid config", func(t *testing.T) {
		config := &domain.Config{
			Database: domain.DatabaseConfig{
				Provider:         "sqlite",
				ConnectionString: ":memory:",
			},
		}

		service := NewService(config, nil)
		repos, err := service.createConnection()

		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if repos == nil {
			t.Fatal("expected repositories to be created")
		}

		defer repos.Close()
	})

	t.Run("error with nil config", func(t *testing.T) {
		service := NewService(nil, nil)
		_, err := service.createConnection()

		if err == nil {
			t.Fatal("expected error with nil config")
		}
	})

	t.Run("error with empty provider", func(t *testing.T) {
		config := &domain.Config{
			Database: domain.DatabaseConfig{
				Provider:         "",
				ConnectionString: ":memory:",
			},
		}

		service := NewService(config, nil)
		_, err := service.createConnection()

		if err == nil {
			t.Fatal("expected error with empty provider")
		}
	})
}

func TestService_Force(t *testing.T) {
	config := &domain.Config{
		Database: domain.DatabaseConfig{
			Provider:         "sqlite",
			ConnectionString: ":memory:",
		},
	}

	service := NewService(config, nil)

	t.Run("error with negative version", func(t *testing.T) {
		ctx := context.Background()
		err := service.Force(ctx, -1)

		if err == nil {
			t.Fatal("expected error with negative version")
		}
	})
}

func TestService_Close(t *testing.T) {
	config := &domain.Config{
		Database: domain.DatabaseConfig{
			Provider:         "sqlite",
			ConnectionString: ":memory:",
		},
	}

	service := NewService(config, nil)
	err := service.Close()

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}
