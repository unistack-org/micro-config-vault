package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/imdario/mergo"
	"github.com/unistack-org/micro/v3/config"
	rutil "github.com/unistack-org/micro/v3/util/reflect"
)

var (
	DefaultStructTag = "vault"
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
	cfg.Timeout = 500 * time.Millisecond
	cfg.MaxRetries = 2
	path := ""
	token := ""
	roleID := ""
	secretID := ""

	if c.opts.Context != nil {
		if v, ok := c.opts.Context.Value(configKey{}).(*api.Config); ok {
			cfg = v
		}

		if v, ok := c.opts.Context.Value(timeoutKey{}).(time.Duration); ok {
			cfg.Timeout = v
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
	if err != nil && !c.opts.AllowFail {
		return nil
	} else if err != nil {
		return err
	}

	if len(token) == 0 {
		rsp, err := cli.Logical().Write("auth/approle/login", map[string]interface{}{
			"role_id":   roleID,
			"secret_id": secretID,
		})
		if err != nil && !c.opts.AllowFail {
			return err
		} else if err == nil {
			token = rsp.Auth.ClientToken
		}
	}
	cli.SetToken(token)

	c.cli = cli
	c.path = path

	return nil
}

func (c *vaultConfig) Load(ctx context.Context, opts ...config.LoadOption) error {
	for _, fn := range c.opts.BeforeLoad {
		if err := fn(ctx, c); err != nil && !c.opts.AllowFail {
			return err
		}
	}

	if c.cli == nil && !c.opts.AllowFail {
		return fmt.Errorf("vault client not created")
	} else if c.cli == nil && c.opts.AllowFail {
		return nil
	}

	pair, err := c.cli.Logical().Read(c.path)
	if err != nil && !c.opts.AllowFail {
		return err
	} else if (pair == nil || pair.Data == nil) && !c.opts.AllowFail {
		return fmt.Errorf("vault path %s not found", c.path)
	}

	if err == nil && pair != nil && pair.Data != nil {
		var data []byte
		var src interface{}
		data, err = json.Marshal(pair.Data["data"])
		if err == nil {
			src, err = rutil.Zero(c.opts.Struct)
			if err == nil {
				err = c.opts.Codec.Unmarshal(data, src)
				if err == nil {
					options := config.NewLoadOptions(opts...)
					mopts := []func(*mergo.Config){mergo.WithTypeCheck}
					if options.Override {
						mopts = append(mopts, mergo.WithOverride)
					}
					if options.Append {
						mopts = append(mopts, mergo.WithAppendSlice)
					}
					err = mergo.Merge(c.opts.Struct, src, mopts...)
				}
			}
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

func (c *vaultConfig) Save(ctx context.Context, opts ...config.SaveOption) error {
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

func (c *vaultConfig) Name() string {
	return c.opts.Name
}

func NewConfig(opts ...config.Option) config.Config {
	options := config.NewOptions(opts...)
	if len(options.StructTag) == 0 {
		options.StructTag = DefaultStructTag
	}
	return &vaultConfig{opts: options}
}
