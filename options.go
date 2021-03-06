package vault

import (
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/unistack-org/micro/v3/config"
)

type configKey struct{}

func Config(cfg *api.Config) config.Option {
	return config.SetOption(configKey{}, cfg)
}

type tokenKey struct{}

func Token(token string) config.Option {
	return config.SetOption(tokenKey{}, token)
}

type addrKey struct{}

func Address(addr string) config.Option {
	return config.SetOption(addrKey{}, addr)
}

type pathKey struct{}

func Path(path string) config.Option {
	return config.SetOption(pathKey{}, path)
}

type roleIDKey struct{}

func RoleID(role string) config.Option {
	return config.SetOption(roleIDKey{}, role)
}

type secretIDKey struct{}

func SecretID(secret string) config.Option {
	return config.SetOption(secretIDKey{}, secret)
}

type timeoutKey struct{}

func Timeout(td time.Duration) config.Option {
	return config.SetOption(timeoutKey{}, td)
}
