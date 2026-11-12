package config

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type File struct {
	GrantTTL      string `yaml:"grant_ttl"`
	DownstreamTTL string `yaml:"downstream_ttl"`
	TokenTTL      string `yaml:"token_ttl"`
}

type Limits struct {
	GrantTTL      time.Duration
	DownstreamTTL time.Duration
	TokenTTL      time.Duration
}

func Load(path string) (Limits, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Limits{}, err
	}
	var file File
	if err := yaml.Unmarshal(raw, &file); err != nil {
		return Limits{}, err
	}
	return file.Limits()
}

func (f File) Limits() (Limits, error) {
	grant, err := time.ParseDuration(f.GrantTTL)
	if err != nil {
		return Limits{}, err
	}
	down, err := time.ParseDuration(f.DownstreamTTL)
	if err != nil {
		return Limits{}, err
	}
	token, err := time.ParseDuration(f.TokenTTL)
	if err != nil {
		return Limits{}, err
	}
	return Limits{GrantTTL: grant, DownstreamTTL: down, TokenTTL: token}, nil
}

func Defaults() Limits {
	limits, err := (File{GrantTTL: "5m", DownstreamTTL: "60s", TokenTTL: "1h"}).Limits()
	if err != nil {
		panic(err)
	}
	return limits
}
