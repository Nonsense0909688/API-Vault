package main

import "time"

type Secret struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type ViewingKey struct {
	Key string `json:"key"`
}

type QueryKey struct {
	Key string `json:"key"`
}

var sessions = map[string]time.Time{}
var secrets = []Secret{}

var encryptionKey []byte

type Config struct {
	AppSettings struct {
		Port    int    `yaml:"port"`
		Address string `yaml:"address"`
	} `yaml:"app-settings"`

	Auth struct {
		Password string `yaml:"password"`
	} `yaml:"auth"`

	Session struct {
		Duration string `yaml:"duration"`
	} `yaml:"session"`
}

var config Config
