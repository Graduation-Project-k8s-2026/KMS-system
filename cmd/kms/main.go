// kms: KMS 외부 사용자용 명령줄 도구. 설정·사용법은 docs/usage.md의 "CLI" 참고.
package main

import "os"

// version은 빌드 때 -ldflags "-X main.version=..."로 채운다.
var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, os.Getenv))
}
