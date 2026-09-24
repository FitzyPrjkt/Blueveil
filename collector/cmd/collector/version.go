// Step 22A: binary identity for release inventory. Reports the module
// path/version and Go toolchain from the build info embedded at compile
// time — no hardcoded version strings to drift from reality. Under `go
// run` or unpackaged builds the version reads "(devel)", which is
// itself honest signal.
package main

import (
	"fmt"
	"runtime/debug"
)

func printVersion() {
	fmt.Println(versionString())
}

func versionString() string {
	mod, ver, goVer := "blueveil/collector", "(devel)", "unknown"
	if info, ok := debug.ReadBuildInfo(); ok {
		goVer = info.GoVersion
		if info.Main.Path != "" {
			mod = info.Main.Path
		}
		if info.Main.Version != "" {
			ver = info.Main.Version
		}
	}
	return fmt.Sprintf("blueveil %s %s %s", mod, ver, goVer)
}
