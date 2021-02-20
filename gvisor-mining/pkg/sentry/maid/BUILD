load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "maid",
    srcs = [
        "maid.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/usermem",
	"//pkg/log"
    ],
)
