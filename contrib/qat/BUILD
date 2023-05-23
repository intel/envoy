load("//bazel:envoy_build_system.bzl", "envoy_contrib_package")
load("@rules_foreign_cc//foreign_cc:configure.bzl", "configure_make")
load(
    "//contrib:all_contrib_extensions.bzl",
    "envoy_contrib_linux_x86_64_constraints",
)

licenses(["notice"])  # Apache 2

envoy_contrib_package()

# Have qatlib outside of any extensions because it may be used by both
# QAT compression library extension and QAT private key provider
# extension.

configure_make(
    name = "qatlib",
    autogen = False,
    configure_in_place = True,
    copts = [
        "-Wno-unused-command-line-argument",
        "-Wno-enum-conversion",
        "-Wno-error=sizeof-array-decay",
        "-Wno-error=unneeded-internal-declaration",
    ],
    lib_source = "@com_github_intel_qatlib//:all",
    # Dynamically linking the libudev, since the libudev is part of building image and container image.
    # So it needn't to be statically linked.
    linkopts = ["-ludev"],
    out_static_libs = [
        "libqat.a",
        "libusdm_drv.a",
        "libadf.a",
        "libosal.a",
    ],
    # The oot qatlib won't install the header files, then need to install header files manually.
    postfix_script = "mkdir -p $INSTALLDIR/include && cp -rL quickassist/include/* $INSTALLDIR/include && cp quickassist/utilities/libusdm_drv/qae_mem.h $INSTALLDIR/include && cp quickassist/lookaside/access_layer/include/*.h $INSTALLDIR/include && cp quickassist/include/dc/*.h $INSTALLDIR/include",
    target_compatible_with = envoy_contrib_linux_x86_64_constraints(),
    visibility = ["//visibility:public"],
    alwayslink = True,
)
