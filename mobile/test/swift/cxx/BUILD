load("@envoy//bazel:envoy_build_system.bzl", "envoy_mobile_package")
load("@envoy_mobile//bazel:apple.bzl", "envoy_mobile_swift_test")

licenses(["notice"])  # Apache 2

envoy_mobile_package()

envoy_mobile_swift_test(
    name = "test",
    srcs = [
        "LogLevelCxxTests.swift",
    ],
    tags = ["no-remote-exec"],  # TODO(32551): Re-enable remote exec
    visibility = ["//visibility:public"],
    deps = [
        "//library/swift/EnvoyCxxSwiftInterop",
    ],
)
