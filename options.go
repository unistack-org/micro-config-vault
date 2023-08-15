package vault

import (
	"net/http"
	"time"

	"github.com/hashicorp/vault/api"
	"go.unistack.org/micro/v4/options"
)

type httpClientKey struct{}

func HTTPClient(c *http.Client) options.Option {
	return options.ContextOption(httpClientKey{}, c)
}

type configKey struct{}

func Config(cfg *api.Config) options.Option {
	return options.ContextOption(configKey{}, cfg)
}

type tokenKey struct{}

func Token(token string) options.Option {
	return options.ContextOption(tokenKey{}, token)
}

type addrKey struct{}

func Address(addr string) options.Option {
	return options.ContextOption(addrKey{}, addr)
}

type pathKey struct{}

func Path(path string) options.Option {
	return options.ContextOption(pathKey{}, path)
}

type roleIDKey struct{}

func RoleID(role string) options.Option {
	return options.ContextOption(roleIDKey{}, role)
}

type secretIDKey struct{}

func SecretID(secret string) options.Option {
	return options.ContextOption(secretIDKey{}, secret)
}

type timeoutKey struct{}

func Timeout(td time.Duration) options.Option {
	return options.ContextOption(timeoutKey{}, td)
}
