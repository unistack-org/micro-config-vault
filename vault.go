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
	ErrInvalidStruct = errors.New("invalid struct specified")
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
	//_, version, err := getKVinfo(c.cli, c.path)
	//if err != nil {
	//	return err
	//}
	pair, err := c.cli.Logical().Read(c.path)
	if err != nil {
		return err
	} else if pair == nil {
		return ErrPathNotExist
	} else if pair.Data == nil {
		return ErrPathNotExist
	}
	//fmt.Printf("%#+v\n", pair)
	//reload secrets from vault's data
	//data := pair.Data
	var data []byte
	data, err = json.Marshal(pair.Data["data"])

	/*
		switch version {
		case 1:
			dataBytes, err = json.Marshal(data)
		case 2:
			dataBytes, err = json.Marshal(data["data"])
		}
	*/

	if err != nil {
		return err
	}

	return json.Unmarshal(data, c.opts.Struct)
}

func (c *vaultConfig) Save(ctx context.Context) error {
	return nil
}

func (c *vaultConfig) String() string {
	return "consul"
}

func NewConfig(opts ...config.Option) config.Config {
	options := config.NewOptions(opts...)
	if len(options.StructTag) == 0 {
		options.StructTag = DefaultStructTag
	}
	return &vaultConfig{opts: options}
}
