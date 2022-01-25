load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_extension",
    "envoy_contrib_package",
)

licenses(["notice"])  # Apache 2

envoy_contrib_package()

envoy_cc_extension(
    name = "config",
    srcs = [
        "extension_validator.cc",
    ],
    hdrs = [
        "extension_validator.h",
    ],
    external_deps = [
        "ssl",
        "abseil_base",
        "abseil_hash",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//envoy/ssl:context_config_interface",
        "//envoy/ssl:ssl_socket_extended_info_interface",
        "//source/common/common:assert_lib",
        "//source/common/common:base64_lib",
        "//source/common/common:c_smart_ptr_lib",
        "//source/common/common:hex_lib",
        "//source/common/common:utility_lib",
        "//source/common/config:datasource_lib",
        "//source/common/config:utility_lib",
        "//source/common/stats:symbol_table_lib",
        "//source/common/stats:utility_lib",
        "//source/extensions/transport_sockets/tls:stats_lib",
        "//source/extensions/transport_sockets/tls:utility_lib",
        "//source/extensions/transport_sockets/tls/cert_validator:cert_validator_lib",
        "@envoy_api//contrib/envoy/extensions/transport_sockets/tls/cert_validator/extension/v3alpha:pkg_cc_proto",
    ],
)
