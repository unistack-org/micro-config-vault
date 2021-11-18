package vault // import "go.unistack.org/micro-config-vault/v3"

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/imdario/mergo"
	"go.unistack.org/micro/v3/config"
	rutil "go.unistack.org/micro/v3/util/reflect"
)

var DefaultStructTag = "vault"

type vaultConfig struct {
	path string
	cli  *api.Client
	opts config.Options
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
	if err != nil {
		c.opts.Logger.Errorf(c.opts.Context, "vault init path %s err: %v", path, err)
		if c.opts.AllowFail {
			return nil
		}
		return err
	}
	c.cli = cli
	c.path = path

	if token != "" {
		cli.SetToken(token)
		return nil
	}

	if roleID == "" || secretID == "" {
		if !c.opts.AllowFail {
			return fmt.Errorf("missing Token or RoleID and SecretID")
		}
		return nil
	}

	rsp, err := cli.Logical().Write("auth/approle/login", map[string]interface{}{
		"role_id":   roleID,
		"secret_id": secretID,
	})

	if err != nil {
		c.opts.Logger.Errorf(c.opts.Context, "vault init approle err: %v", err)
		if !c.opts.AllowFail {
			return err
		}
	} else if err == nil {
		cli.SetToken(rsp.Auth.ClientToken)
	}

	return nil
}

func (c *vaultConfig) Load(ctx context.Context, opts ...config.LoadOption) error {
	if err := config.DefaultBeforeLoad(ctx, c); err != nil {
		return err
	}

	if c.cli == nil {
		c.opts.Logger.Errorf(c.opts.Context, "vault load err: %v", fmt.Errorf("vault client not created"))
		if !c.opts.AllowFail {
			return fmt.Errorf("vault client not created")
		}
		return config.DefaultAfterLoad(ctx, c)
	}

	pair, err := c.cli.Logical().Read(c.path)
	if err != nil {
		c.opts.Logger.Errorf(c.opts.Context, "vault load path %s err: %v", c.path, err)
		if !c.opts.AllowFail {
			return err
		}
		return config.DefaultAfterLoad(ctx, c)
	}

	if pair == nil || pair.Data == nil {
		c.opts.Logger.Errorf(c.opts.Context, "vault load path %s err: %v", c.path, fmt.Errorf("not found"))
		if !c.opts.AllowFail {
			return fmt.Errorf("vault path %s not found", c.path)
		}
		return config.DefaultAfterLoad(ctx, c)
	}

	var data []byte
	var src interface{}
	data, err = json.Marshal(pair.Data["data"])
	if err != nil {
		c.opts.Logger.Errorf(c.opts.Context, "vault load path %s err: %v", c.path, err)
		if !c.opts.AllowFail {
			return err
		}
		return config.DefaultAfterLoad(ctx, c)
	}

	src, err = rutil.Zero(c.opts.Struct)
	if err == nil {
		err = c.opts.Codec.Unmarshal(data, src)
	}

	if err != nil {
		c.opts.Logger.Errorf(c.opts.Context, "vault load path %s err: %v", c.path, err)
		if !c.opts.AllowFail {
			return err
		}
		return config.DefaultAfterLoad(ctx, c)
	}

	options := config.NewLoadOptions(opts...)
	mopts := []func(*mergo.Config){mergo.WithTypeCheck}
	if options.Override {
		mopts = append(mopts, mergo.WithOverride)
	}
	if options.Append {
		mopts = append(mopts, mergo.WithAppendSlice)
	}
	err = mergo.Merge(c.opts.Struct, src, mopts...)

	if err != nil {
		c.opts.Logger.Errorf(c.opts.Context, "vault load path %s err: %v", c.path, err)
		if !c.opts.AllowFail {
			return err
		}
	}

	if err := config.DefaultAfterLoad(ctx, c); err != nil {
		return err
	}

	return nil
}

func (c *vaultConfig) Save(ctx context.Context, opts ...config.SaveOption) error {
	if err := config.DefaultBeforeSave(ctx, c); err != nil {
		return err
	}

	if err := config.DefaultAfterSave(ctx, c); err != nil {
		return err
	}

	return nil
}

func (c *vaultConfig) String() string {
	return "vault"
}

func (c *vaultConfig) Name() string {
	return c.opts.Name
}

func (c *vaultConfig) Watch(ctx context.Context, opts ...config.WatchOption) (config.Watcher, error) {
	w := &vaultWatcher{
		cli:   c.cli,
		path:  c.path,
		opts:  c.opts,
		wopts: config.NewWatchOptions(opts...),
		done:  make(chan struct{}),
		vchan: make(chan map[string]interface{}),
		echan: make(chan error),
	}

	go w.run()

	return w, nil
}

func NewConfig(opts ...config.Option) config.Config {
	options := config.NewOptions(opts...)
	if len(options.StructTag) == 0 {
		options.StructTag = DefaultStructTag
	}
	return &vaultConfig{opts: options}
}
