package flags

import "github.com/urfave/cli/v2"

const envVarPrefix = "SIGNATURE"

func prefixEnvVars(name string) []string {
	return []string{envVarPrefix + "_" + name}
}

var (
	LevelDbPathFlag = &cli.StringFlag{
		Name:    "master-db-host",
		Usage:   "The path of the leveldb",
		EnvVars: prefixEnvVars("LEVEL_DB_PATH"),
		Value:   "./",
	}
)

var requireFlags = []cli.Flag{
	LevelDbPathFlag,
}

var optionalFlags = []cli.Flag{}

var Flags []cli.Flag

func init() {
	Flags = append(requireFlags, optionalFlags...)
}
