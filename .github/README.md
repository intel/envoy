# Intel managed distribution of Istio

## Introduction

Intel managed distribution of Istio is a project aiming to showcase and
integrate various Intel technologies into Istio and Envoy. The focus is
in letting both upstream community and users know what Intel is working
on, finding gaps in upstream project features in relation to hardware
enablement, and testing and deploying Intel features for Istio service
mesh.

Intel managed distribution of Istio consists of the following source
code repositories:

* https://github.com/intel/envoy

* https://github.com/intel/envoy-go-control-plane

* https://github.com/intel/istio

* https://github.com/intel/istio-api

* https://github.com/intel/istio-proxy

## Project goals and relation to upstream projects

The goal of the project is not to maintain permanent Istio and Envoy
forks, but rather have a place to test and maintain features which can
be later upstreamed. When features are added to Istio and Envoy
upstream, they will be removed from this distribution, reducing the
difference to upstream. We intend to have Intel distribution for Istio
always compatible with the usual APIs, configuration formats, and
tooling. We will just extend Istio and Envoy with new extensions and
APIs.

## Release branch policy

Intel distribution for Istio will track the latest Envoy release in use
by the latest release of Istio. The branch will be named after Istio
release version numbers. For example, Envoy version 1.23, which is used
by Istio version 1.15, will be tracked in Envoy in a branch named
release-1.15-intel. The releases will be tagged with a similar naming
scheme for example 1.15.3-intel.2, which would indicate Envoy
used by the second Intel distribution for Istio release done on top of
Istio upstream 1.15.3 release.

## Features

### AVX-512

Envoy has support for CryptoMb private key provider plugin. This plugin
can be configured using Istio to accelerate TLS handshakes using RSA
for signing or decryption.

### Intel QuickAssist Technology (QAT) 2.0

QAT 2.0 (using QAT 4xxx generation devices present in future Xeon
Scalable processors) can be used to accelerate TLS handshakes using
RSA. QAT is also used to accelerate HTTP compression for gzip
encoding.

### SGX

SGX mTLS support helps maintain Envoy private key security by storing
the keys inside encrypted SGX enclaves.

## Deployment

TBD

## Development

This repository will be used in developing further support for
Intel technologies as briefly described above. The development
results will be made into Pull Requests for the upstream project.
Occationally upstream Pull Requests will be backported to earlier Istio
releases if needed. Ordinary Envoy development shall take place in the
Envoy upstream repository.

## Building

Envoy with Intel enabled technologies is compiled from the top-level
source directory similar to an upstream build with:
```
./ci/run_envoy_docker.sh './ci/do_ci.sh bazel.dev.contrib'
```

[Upstream build instructions](https://www.envoyproxy.io/docs/envoy/latest/start/building#)
also apply.

## Upstream README

Upstream [README](/README.md).

## Limitations

This version of the software is pre-production release and is meant for
evaluation and trial purposes only.
