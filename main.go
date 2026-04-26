package main

import "github.com/complykit/complykit/cmd"

// Version is set at build time by GoReleaser via ldflags.
var version = "dev"

func main() {
	cmd.SetVersion(version)
	cmd.Execute()
}
