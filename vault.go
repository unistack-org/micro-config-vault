package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"dario.cat/mergo"
	"github.com/hashicorp/vault/api"
	"go.unistack.org/micro/v3/config"
	rutil "go.unistack.org/micro/v3/util/reflect"
)

var DefaultStructTag = "vault"

type vaultConfig struct {
	path     string
	token    string
	roleID   string
	secretID string
	cli      *api.Client
	opts     config.Options
}

func (c *vaultConfig) Options() config.Options {
	return c.opts
}

func (c *vaultConfig) Init(opts ...config.Option) error {
	for _, o := range opts {
		o(&c.opts)
	}

	if err := config.DefaultBeforeInit(c.opts.Context, c); err != nil && !c.opts.AllowFail {
		return err
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

		if v, ok := c.opts.Context.Value(httpClientKey{}).(*http.Client); ok {
			cfg.HttpClient = v
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
		if !c.opts.AllowFail {
			return err
		}

		if err = config.DefaultAfterInit(c.opts.Context, c); err != nil && !c.opts.AllowFail {
			return err
		}

		return nil
	}
	c.cli = cli
	c.path = path
	c.token = token
	c.roleID = roleID
	c.secretID = secretID

	if err = c.setToken(); err != nil && !c.opts.AllowFail {
		return err
	}

	if err := config.DefaultAfterInit(c.opts.Context, c); err != nil && !c.opts.AllowFail {
		return err
	}

	return nil
}

func (c *vaultConfig) setToken() error {
	if c.token != "" {
		c.cli.SetToken(c.token)
	}

	if c.roleID != "" && c.secretID != "" {
		rsp, err := c.cli.Logical().Write("auth/approle/login", map[string]interface{}{
			"role_id":   c.roleID,
			"secret_id": c.secretID,
		})
		if err != nil {
			if !c.opts.AllowFail {
				return err
			}
		} else if err == nil {
			c.cli.SetToken(rsp.Auth.ClientToken)
		}
	}

	return nil
}

func (c *vaultConfig) Load(ctx context.Context, opts ...config.LoadOption) error {
	if c.opts.SkipLoad != nil && c.opts.SkipLoad(ctx, c) {
		return nil
	}

	if err := config.DefaultBeforeLoad(ctx, c); err != nil {
		return err
	}

	options := config.NewLoadOptions(opts...)
	if c.cli == nil {
		c.opts.Logger.Errorf(c.opts.Context, "vault load err: %v", fmt.Errorf("vault client not created"))
		if !c.opts.AllowFail {
			return fmt.Errorf("vault client not created")
		}
		return config.DefaultAfterLoad(ctx, c)
	}

	pair, err := c.cli.Logical().Read(c.path)
	if err != nil {
		err = fmt.Errorf("vault load path %s err: %w", c.path, err)
		if !c.opts.AllowFail {
			return err
		}
		return config.DefaultAfterLoad(ctx, c)
	}

	if pair == nil || pair.Data == nil {
		err = fmt.Errorf("vault load path %s err: %w", c.path, fmt.Errorf("not found"))
		if !c.opts.AllowFail {
			return err
		}
		return config.DefaultAfterLoad(ctx, c)
	}

	var data []byte
	var src interface{}
	data, err = json.Marshal(pair.Data["data"])
	if err != nil {
		err = fmt.Errorf("vault load path %s err: %w", c.path, err)
		if !c.opts.AllowFail {
			return err
		}
		return config.DefaultAfterLoad(ctx, c)
	}

	dst := c.opts.Struct
	if options.Struct != nil {
		dst = options.Struct
	}

	src, err = rutil.Zero(dst)
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

	mopts := []func(*mergo.Config){mergo.WithTypeCheck}
	if options.Override {
		mopts = append(mopts, mergo.WithOverride)
	}
	if options.Append {
		mopts = append(mopts, mergo.WithAppendSlice)
	}
	err = mergo.Merge(dst, src, mopts...)
	if err != nil {
		err = fmt.Errorf("vault load path %s err: %w", c.path, err)
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
	if c.opts.SkipSave != nil && c.opts.SkipSave(ctx, c) {
		return nil
	}

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
