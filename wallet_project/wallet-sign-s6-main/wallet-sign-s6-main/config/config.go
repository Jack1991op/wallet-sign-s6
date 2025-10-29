package config

import (
	"os"

	"gopkg.in/yaml.v2"

	"github.com/ethereum/go-ethereum/log"
)

type ServerConfig struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
}

type Config struct {
	LevelDbPath     string       `yaml:"level_db_path"`
	RpcServer       ServerConfig `yaml:"rpc_server"`
	CredentialsFile string       `yaml:"credentials_file"`
	KeyName         string       `yaml:"key_name"`
	KeyPath         string       `yaml:"key_path"`
	HsmEnable       bool         `yaml:"hsm_enable"`
	Chains          []string     `yaml:"chains"`
}

func NewConfig(path string) (*Config, error) {
	var config = new(Config)
	h := log.NewTerminalHandler(os.Stdout, true)
	log.SetDefault(log.NewLogger(h))

	data, err := os.ReadFile(path)
	if err != nil {
		log.Error("read config file error", "err", err)
		return nil, err
	}

	err = yaml.Unmarshal(data, config)
	if err != nil {
		log.Error("unmarshal config file error", "err", err)
		return nil, err
	}
	return config, nil
}

const UnsupportedChain = "Unsupport chain"
const UnsupportedOperation = UnsupportedChain
