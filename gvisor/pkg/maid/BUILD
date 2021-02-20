load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "maid",
    srcs = [
        "maid.go",
    ],
    # visibility = ["//pkg/sentry:internal"],
    visibility = [
        "//visibility:public",
    ],
    deps = [
        "//pkg/usermem",
	    "//pkg/log",
    ],
)
