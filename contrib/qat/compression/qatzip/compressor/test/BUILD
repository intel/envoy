load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_test",
    "envoy_cc_fuzz_test",
    "envoy_contrib_package",
)

licenses(["notice"])  # Apache 2

envoy_contrib_package()

envoy_cc_test(
    name = "qatzip_compressor_impl_test",
    srcs = ["qatzip_compressor_impl_test.cc"],
    deps = [
        "//contrib/qat/compression/qatzip/compressor/source:config",
        "//source/extensions/compression/gzip/decompressor:zlib_decompressor_impl_lib",
        "//test/mocks/server:factory_context_mocks",
        "//test/test_common:utility_lib",
    ],
)

envoy_cc_fuzz_test(
    name = "compressor_fuzz_test",
    srcs = ["compressor_fuzz_test.cc"],
    corpus = "compressor_corpus",
    deps = [
        "//source/common/buffer:buffer_lib",
        "//source/common/common:assert_lib",
        "//contrib/qat/compression/qatzip/compressor/source:config",
        "//source/extensions/compression/gzip/decompressor:zlib_decompressor_impl_lib",
        "//test/mocks/server:factory_context_mocks",
    ],
)
