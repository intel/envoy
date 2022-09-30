#! /bin/bash

# Usage:
# ./.github/workflows/build.sh 

# this script will modified upper directory istio-proxy repo
# if self-used should attention that whether the upper directory have its own developing istio-proxy
#first build should give permission to docker volumes
#sudo chmod -R 777 /var/lib/docker/volumes 

UPDATE_BRANCH=${UPDATE_BRANCH:-"release-1.15-intel"}
# To maintain build repo is latest
cd ..
rm -rf istio-proxy
git clone -b ${UPDATE_BRANCH} https://github.com/intel/istio-proxy.git
cp -rf envoy/ istio-proxy/ 
cd istio-proxy
git clone -b ${UPDATE_BRANCH} https://github.com/intel/istio.git

# Replace upstream envoy with local envoy in build file
# In envoy repo we still use sed method because we need to catch PR. Only use update_envoy.sh cannot get pr patch.
cp -f WORKSPACE WORKSPACE.bazel
sed  -i '/http_archive(/{:a;N;/)/!ba;s/.*name = "envoy".*/local_repository(\
    name = "envoy",\
    path = "envoy",\
)/g}' WORKSPACE.bazel

# build envoy binary in container with sgx
BUILD_WITH_CONTAINER=1 make build_envoy 
BUILD_WITH_CONTAINER=1 make exportcache
# sgx build container would cause build proxyv2 image failed in release-1.15
unset IMG
# build istio and export env
TAG=${TAG:-"pre-build"}
(cd istio;make build)
# replace upstream envoy with local envoy in build proxyv2 image
cp -rf out/linux_amd64/envoy istio/out/linux_amd64/release/envoy
# build proxyv2 image
cd istio
make docker.proxyv2
