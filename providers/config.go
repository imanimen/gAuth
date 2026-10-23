package providers

import (
	"os"
	"time"

	"github.com/joho/godotenv"
)

// IConfig provides access to application configuration values.
type IConfig interface {
	// Get returns the value of the given key. It looks up the process
	// environment first and falls back to values loaded from an optional
	// .env file. It returns an empty string when the key is not set.
	Get(key string) string
	// Has reports whether the given key is set.
	Has(key string) bool
	// Port returns the HTTP port the API server should listen on.
	Port() string
	// Secret returns the JWT signing secret.
	Secret() string
	// TokenTTL returns the access token time-to-live as a duration.
	TokenTTL() time.Duration
	// Version returns the public API version identifier.
	Version() string
	// DSN returns the database data source name.
	DSN() string
	// SwaggerEnabled reports whether the Swagger UI should be exposed.
	SwaggerEnabled() bool
}

type config struct {
	env map[string]string
}

// NewConfig builds an IConfig from the process environment merged with an
// optional .env file. Process environment values always take precedence.
// A missing .env file is not an error.
func NewConfig() IConfig {
	return &config{env: loadEnv()}
}

func NewTestConfig(values map[string]string) IConfig {
	env := loadEnv()
	for key, value := range values {
		env[key] = value
	}
	return &config{env: env}
}

func loadEnv() map[string]string {
	env := make(map[string]string)
	for _, entry := range os.Environ() {
		key, value, ok := splitEnv(entry)
		if ok {
			env[key] = value
		}
	}
	// Optional .env file: only fills in keys that are not already set.
	if pairs, err := godotenv.Read(); err == nil {
		for key, value := range pairs {
			if _, exists := env[key]; !exists {
				env[key] = value
			}
		}
	}
	return env
}

func splitEnv(entry string) (string, string, bool) {
	for i := 0; i < len(entry); i++ {
		if entry[i] == '=' {
			return entry[:i], entry[i+1:], true
		}
	}
	return "", "", false
}

func (c *config) Get(key string) string {
	return c.env[key]
}

func (c *config) Has(key string) bool {
	_, ok := c.env[key]
	return ok
}

func (c *config) Port() string {
	if port := c.Get("PORT"); port != "" {
		return port
	}
	return "8080"
}

func (c *config) Secret() string {
	// Keep the legacy env name working for existing deployments.
	if secret := c.Get("SECRET"); secret != "" {
		return secret
	}
	return c.Get("jWT")
}

func (c *config) TokenTTL() time.Duration {
	if v := c.Get("TOKEN_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return 10 * time.Minute
}

func (c *config) Version() string {
	if v := c.Get("apiVersion"); v != "" {
		return v
	}
	return "v1"
}

func (c *config) DSN() string {
	return c.Get("dsn")
}

func (c *config) SwaggerEnabled() bool {
	switch c.Get("ENABLE_SWAGGER") {
	case "1", "true", "TRUE", "True", "yes", "on":
		return true
	}
	return false
}
