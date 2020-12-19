package vault

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/hashicorp/vault/api"
	"github.com/unistack-org/micro/v3/config"
)

var (
	DefaultStructTag = "vault"
	ErrPathNotExist  = errors.New("path is not exist")
)

type vaultConfig struct {
	opts config.Options
	cli  *api.Client
	path string
}

func (c *vaultConfig) Options() config.Options {
	return c.opts
}

func (c *vaultConfig) Init(opts ...config.Option) error {
	for _, o := range opts {
		o(&c.opts)
	}

	if c.opts.Codec == nil {
		return config.ErrCodecMissing
	}

	cfg := api.DefaultConfig()
	path := ""
	token := ""
	roleID := ""
	secretID := ""

	if c.opts.Context != nil {
		if v, ok := c.opts.Context.Value(configKey{}).(*api.Config); ok {
			cfg = v
		}

		if v, ok := c.opts.Context.Value(addrKey{}).(string); ok {
			cfg.Address = v
		}

		if v, ok := c.opts.Context.Value(tokenKey{}).(string); ok {
			token = v
		}

		if v, ok := c.opts.Context.Value(pathKey{}).(string); ok {
			path = v
		}

		if v, ok := c.opts.Context.Value(roleIDKey{}).(string); ok {
			roleID = v
		}

		if v, ok := c.opts.Context.Value(secretIDKey{}).(string); ok {
			secretID = v
		}

	}

	cli, err := api.NewClient(cfg)
	if err != nil {
		return err
	}

	if len(token) == 0 {
		rsp, err := cli.Logical().Write("auth/approle/login", map[string]interface{}{
			"role_id":   roleID,
			"secret_id": secretID,
		})
		if err != nil {
			return err
		}
		token = rsp.Auth.ClientToken
	}
	cli.SetToken(token)

	c.cli = cli
	c.path = path

	return nil
}

func (c *vaultConfig) Load(ctx context.Context) error {
	for _, fn := range c.opts.BeforeLoad {
		if err := fn(ctx, c); err != nil && !c.opts.AllowFail {
			return err
		}
	}

	pair, err := c.cli.Logical().Read(c.path)
	if err != nil && !c.opts.AllowFail {
		return err
	} else if (pair == nil || pair.Data == nil) && !c.opts.AllowFail {
		return ErrPathNotExist
	}

	if err == nil && pair != nil && pair.Data != nil {
		var data []byte
		data, err = json.Marshal(pair.Data["data"])
		if err == nil {
			err = c.opts.Codec.Unmarshal(data, c.opts.Struct)
		}
		if err != nil && !c.opts.AllowFail {
			return err
		}
	}

	for _, fn := range c.opts.AfterLoad {
		if err := fn(ctx, c); err != nil && !c.opts.AllowFail {
			return err
		}
	}

	return nil
}

func (c *vaultConfig) Save(ctx context.Context) error {
	for _, fn := range c.opts.BeforeSave {
		if err := fn(ctx, c); err != nil && !c.opts.AllowFail {
			return err
		}
	}

	for _, fn := range c.opts.AfterSave {
		if err := fn(ctx, c); err != nil && !c.opts.AllowFail {
			return err
		}
	}

	return nil
}

func (c *vaultConfig) String() string {
	return "vault"
}

func NewConfig(opts ...config.Option) config.Config {
	options := config.NewOptions(opts...)
	if len(options.StructTag) == 0 {
		options.StructTag = DefaultStructTag
	}
	return &vaultConfig{opts: options}
}
