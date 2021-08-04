package vault

import (
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/hashicorp/vault/api"
	"github.com/unistack-org/micro/v3/config"
	"github.com/unistack-org/micro/v3/util/jitter"
	rutil "github.com/unistack-org/micro/v3/util/reflect"
)

type vaultWatcher struct {
	cli   *api.Client
	path  string
	opts  config.Options
	wopts config.WatchOptions
	done  chan struct{}
	vchan chan map[string]interface{}
	echan chan error
}

func (w *vaultWatcher) run() {
	ticker := jitter.NewTicker(w.wopts.MinInterval, w.wopts.MaxInterval)
	defer ticker.Stop()

	src := w.opts.Struct
	if w.wopts.Struct != nil {
		src = w.wopts.Struct
	}

	for {
		select {
		case <-w.done:
			return
		case <-ticker.C:
			dst, err := rutil.Zero(src)
			if err != nil {
				w.echan <- err
				return
			}

			pair, err := w.cli.Logical().Read(w.path)
			if err != nil {
				w.echan <- err
				return
			} else if pair == nil || pair.Data == nil {
				w.echan <- fmt.Errorf("vault path %s not found", w.path)
				return
			}

			var data []byte
			data, err = json.Marshal(pair.Data["data"])
			if err == nil {
				err = w.opts.Codec.Unmarshal(data, dst)
			}
			if err != nil {
				w.echan <- err
				return
			}

			srcmp, err := rutil.StructFieldsMap(src)
			if err != nil {
				w.echan <- err
				return
			}

			dstmp, err := rutil.StructFieldsMap(dst)
			if err != nil {
				w.echan <- err
				return
			}

			for sk, sv := range srcmp {
				if reflect.DeepEqual(dstmp[sk], sv) {
					delete(dstmp, sk)
				}
			}
			if len(dstmp) > 0 {
				w.vchan <- dstmp
				src = dst
			}
		}
	}
}

func (w *vaultWatcher) Next() (map[string]interface{}, error) {
	select {
	case <-w.done:
		break
	case err := <-w.echan:
		return nil, err
	case v, ok := <-w.vchan:
		if !ok {
			break
		}
		return v, nil
	}
	return nil, config.ErrWatcherStopped
}

func (w *vaultWatcher) Stop() error {
	close(w.done)
	return nil
}
