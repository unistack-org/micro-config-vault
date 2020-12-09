package vault

import (
	"encoding/json"
	"fmt"

	"github.com/hashicorp/vault/api"
)

func getKVinfo(cli *api.Client, path string) (string, int, error) {
	info, err := getKVmount(cli, path)
	if err != nil {
		return "", 0, err
	}

	switch info {
	case "1":
		return "", 1, nil
	case "2":
		return "data", 2, nil
	}

	return "", 0, fmt.Errorf("Vault engine version info not found: %s", path)
}

func getKVmount(cli *api.Client, path string) (string, error) {
	requestpath := "/v1/sys/mounts/" + path
	rsp, err := cli.RawRequest(cli.NewRequest("GET", requestpath))
	if err != nil {
		return "", err
	}
	defer rsp.Body.Close()

	type MountInfo struct {
		Data struct {
			Options struct {
				Version string `json:"version"`
			} `json:"options"`
		} `json:"data"`
	}

	info := &MountInfo{}
	if err = json.NewDecoder(rsp.Body).Decode(info); err != nil {
		return "", err
	}

	if info.Data.Options.Version == "" {
		return "1", nil
	}

	return info.Data.Options.Version, nil
}
