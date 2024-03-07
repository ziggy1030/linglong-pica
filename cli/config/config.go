package config

import (
	"encoding/json"
	"os"

	"pkg.deepin.com/linglong/pica/tools/log"
)

type Config struct {
	Id            string `yaml:"id" json:"id"`
	Version       string `yaml:"version" json:"version"`
	Source        string `yaml:"source" json:"source"`
	DistroVersion string `yaml:"distro_version" json:"distro_version"`
	Arch          string `yaml:"arch" json:"arch"`
}

func NewConfig() *Config {
	return &Config{}
}
func (c *Config) SaveOrUpdateConfigJson(path string) bool {
	// 创建 pica 工具配置文件
	log.Logger.Infof("create save file: %s", path)

	jsonBytes, err := json.Marshal(c)
	if err != nil {
		log.Logger.Errorf("JSON marshaling failed: %s", err)
	}

	err = os.WriteFile(path, jsonBytes, 0644)
	if err != nil {
		log.Logger.Fatalf("save to %s failed!", path)
		return false
	}

	return true
}
