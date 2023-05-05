load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_test",
    "envoy_cc_fuzz_test",
    "envoy_contrib_package",
)

licenses(["notice"])  # Apache 2

envoy_contrib_package()

envoy_cc_fuzz_test(
    name = "sgx_fuzz_test",
    srcs = ["sgx_fuzz_test.cc"],
    corpus = "sgx_corpus",
    copts = ["-I external/pkcs11/include/pkcs11-v2.40"],
    deps = [
        "//source/common/common:assert_lib",
        "//contrib/sgx/private_key_providers/source:config",
        "//test/mocks/server:factory_context_mocks",
    ],
)
