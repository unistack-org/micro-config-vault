package vault

import (
	"context"
	"testing"

	"go.unistack.org/micro/v4/codec"
	"go.unistack.org/micro/v4/config"
	"go.unistack.org/micro/v4/options"
)

func TestInit(t *testing.T) {
	c := NewConfig(
		options.Context(context.TODO()),
		options.Codec(codec.NewCodec()),
		config.BeforeInit(func(ctx context.Context, c config.Config) error {
			return c.Init(Token("tkn"), config.BeforeInit(nil))
		}),
	)

	if err := c.Init(); err != nil {
		t.Fatal(err)
	}
}
