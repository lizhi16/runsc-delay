load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "monitor",
    srcs = [
        "monitor.go",
    ],
    visibility = [
        "//pkg:__subpackages__",
        "//runsc:__subpackages__",
        "//test:__subpackages__",
    ],
    deps = [
	"//pkg/log",
        "@com_github_golang_protobuf//proto:go_default_library",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
