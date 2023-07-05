# How to enable QAT oot in Istio 
## 1. Enviornment
```
Processor: SPR XCC 
System: Ubuntu 22.04 
Kernel: Linux r027s014.fl30lne001 5.15.0-73-generic #80-Ubuntu SMP Mon May 15 15:18:26 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux 

```
## 2. Install QAT oot driver
### 2.1 Download driver
Get QAT oot driver from https://www.intel.com/content/www/us/en/download/765501/777529/intel-quickassist-technology-driver-for-linux-hw-version-2-0.html.  
### 2.2 Install driver with vf mode
```
tar -xzvf QAT20.L.1.0.20-00008.tar.gz
./configure --enable-icp-sriov=host
sudo make install
```  
### 2.3 Configuration for QAT
```
sudo mkdir /etc/systemd/system/containerd.service.d
sudo bash -c 'cat <<EOF >>/etc/systemd/system/containerd.service.d/memlock.conf
[Service]
LimitMEMLOCK=134217728
EOF'

sudo systemctl daemon-reload
sudo systemctl restart containerd
```
```
sudo cp /etc/security/limits.conf /etc/security/limits.conf.qatlib_bak
echo `whoami` - memlock 500000  | sudo tee -a /etc/security/limits.conf > /dev/null
```
Add user to qat group:
```
sudo usermod -a -G qat `whoami`
sudo su -l $USER
```
Add `rw` to qat devices:
```
sudo chmod a+rw /dev/uio*
sudo chmod a+rw /dev/qat_*
sudo chmod a+rw /dev/usdm*
```
## 3. Install k8s cluster
Install k8s cluster with kubeadm
## 4. Install QAT oot devive plugin
Build and install QAT oot devive plugin as "BKM to make k8s-qat-device-plugin use the OOT driver (with minikube)"
## 5. Build envoy in Istio-proxy
### 5.1 Dependencies
```
sudo wget -O /usr/local/bin/bazel https://github.com/bazelbuild/bazelisk/releases/latest/download/bazelisk-linux-$([ $(uname -m) = "aarch64" ] && echo "arm64" || echo "amd64")
sudo chmod +x /usr/local/bin/bazel

sudo apt-get install \
   autoconf \
   curl \
   libtool \
   patch \
   python3-pip \
   unzip \
   virtualenv
```
And you need to install `golang` as well.
### 5.2 Build envoy with clang 14.0.0 in Istio-proxy
```
 git clone https://github.com/istio/proxy.git -b release-1.18
 cd proxy
 git clone https://github.com/intel/envoy.git -b oot_qat_build_direct_static
 cd envoy
 wget https://github.com/llvm/llvm-project/releases/download/llvmorg-14.0.0/clang+llvm-14.0.0-x86_64-linux-gnu-ubuntu-18.04.tar.xz
 tar -xvf clang+llvm-14.0.0-x86_64-linux-gnu-ubuntu-18.04.tar.xz
 bazel/setup_clang.sh <ABSOLUTE_PATH_TO_EXTRACTED_CLANG_LLVM>
 cp ./clang.bazelrc ../
 cd ..
```
```
 vim WORKSPACE
 change WORKSPACE as following:
 "
  # # To override with local envoy, just pass `--override_repository=envoy=/PATH/TO/ENVOY` to Bazel or
  # # persist the option in `user.bazelrc`.
  # http_archive(
  #     name = "envoy",
  #     sha256 = ENVOY_SHA256,
  #     strip_prefix = ENVOY_REPO + "-" + ENVOY_SHA,
  #     url = "https://github.com/" + ENVOY_ORG + "/" + ENVOY_REPO + "/archive/" + ENVOY_SHA + ".tar.gz",
  # )

  local_repository(
      name = "envoy",
      # Relative paths are also supported.
      path = "envoy",
  )
 "
```
```
make build_envoy
```
## 6. Build and install istio
### 6.1 Build istio images
```
git clone https://github.com/istio/istio.git -b release-1.18
cd istio
make build
cp -f ~/proxy/bazel-bin/envoy ./out/linux_amd64/release/envoy
make docker
```
use `docker tag` to tag proxyv2 and pilot builded images to "docker.io/proxyv2:v1" as example. 
### 6.2 Install istio with qat
```
vim intel-istio-qat-hw.yaml

# Feature: TLS handshake acceleration using QAT2.0 crypto
# Config: Envoy + BoringSSL + QAT2.0
# Requires: 4th Gen Intel® Xeon® Scalable processor
# Applies: Istio ingress gateway and sidecars

apiVersion: install.istio.io/v1alpha1
kind: IstioOperator
metadata:
  name: qat
  namespace: istio-system
spec:
  profile: default
  tag: v1
  hub: docker.io

  components:
    ingressGateways:
    - name: istio-ingressgateway
      enabled: true
      k8s:
        # Ingress gateway needs to have IPC_LOCK capability and the
        # QAT resources manually added, because the template
        # injection isn't supported for gateways.
        overlays:
        - kind: Deployment
          name: istio-ingressgateway
          patches:
          - path: spec.template.spec.containers.[name:istio-proxy].securityContext.capabilities.add
            value: [ "IPC_LOCK" ]
        resources:
          requests:
            qat.intel.com/cy2_dc2: '1'
            cpu: 2000m
            memory: 4096Mi
          limits:
            qat.intel.com/cy2_dc2: '1'
            cpu: 2000m
            memory: 4096Mi
        podAnnotations: # this controls the SDS service which configures ingress gateway
          proxy.istio.io/config: |
            privateKeyProvider:
              qat:
                pollDelay: 2ms

# warning: only for debug, you need to comment the following code when benchmark.
  values:
    global:
      logging:
        level: all:debug
      proxy:
        logLevel: debug

```
```
istioctl install -y -f ./intel-istio-qat-hw.yaml
```
## 7. Ingress gateway test case
### 7.1 Setup httpbin
```
kubectl apply -f samples/httpbin/httpbin.yaml
```
### 7.2 Generate TLS secret
```
vim ./generate_secret.sh

#!/bin/bash

# generate CA cerficate
openssl genrsa -out fortio.com.key 2048
openssl req -new -x509 -days 365 -key fortio.com.key -subj "/C=CN/ST=GD/L=SZ/O=httpbin.example.com, Inc./CN=httpbin.example.com Root CA" -out fortio.com.crt

# generate CSR
openssl req -newkey rsa:2048 -nodes -keyout httpbin.fortio.com.key -subj "/C=CN/ST=GD/L=SZ/O=httpbin.example.com, Inc./CN=*.httpbin.example.com" -out httpbin.fortio.com.csr
openssl x509 -req -extfile <(printf "subjectAltName=DNS:httpbin.example.com,DNS:www.httpbin.example.com") -days 365 -in httpbin.fortio.com.csr -CA fortio.com.crt -CAkey fortio.com.key -CAcreateserial -out httpbin.fortio.com.crt

# upload key and crt as a secret
kubectl create -n istio-system secret tls httpbin-fortio-credential --key=httpbin.fortio.com.key --cert=httpbin.fortio.com.crt

```
### 7.3 Create gateway for httpbin
```
vim gateway-https.yaml

apiVersion: networking.istio.io/v1alpha3
kind: Gateway
metadata:
  name: gateway-https
spec:
  selector:
    istio: ingressgateway # use Istio default gateway implementation
  servers:
  - port:
      number: 443
      name: https
      protocol: HTTPS
    tls:
      mode: SIMPLE
      credentialName: httpbin-fortio-credential # must be the same as secret
    hosts:
    - "httpbin.example.com"

---
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: fortio-server-https
spec:
  hosts:
  - "httpbin.example.com"
  gateways:
  - gateway-https
  http:
  - route:
    - destination:
        host: httpbin
        port:
          number: 8000

```
```
kubectl apply -f gateway-https.yaml
```
### 7.4 Test ingress tls
```
sudo sed -i "/127.0.0.1/a <host-ip> httpbin.example.com" /etc/hosts
```
```
get ingress gateway secure port:
kubectl get svc -A |grep ingress

istio-system   istio-ingressgateway   LoadBalancer   10.111.236.136   <pending>     15021:32635/TCP,80:30842/TCP,443:32004/TCP   3h9m

```
```
curl -v -I "https://httpbin.example.com:32004/" -k
```
and the successful log like below:
```
* Uses proxy env variable no_proxy == 'localhost,127.0.0.1,10.45.247.79,fortio.com,10.244.0.0/16,10.96.0.0/16,.svc,172.16.27.140'
*   Trying 10.45.247.79:32004...
* Connected to httpbin.example.com (10.45.247.79) port 32004 (#0)
* ALPN, offering h2
* ALPN, offering http/1.1
* TLSv1.0 (OUT), TLS header, Certificate Status (22):
* TLSv1.3 (OUT), TLS handshake, Client hello (1):
* TLSv1.2 (IN), TLS header, Certificate Status (22):
* TLSv1.3 (IN), TLS handshake, Server hello (2):
* TLSv1.2 (IN), TLS header, Finished (20):
* TLSv1.2 (IN), TLS header, Supplemental data (23):
* TLSv1.3 (IN), TLS handshake, Encrypted Extensions (8):
* TLSv1.3 (IN), TLS handshake, Certificate (11):
* TLSv1.3 (IN), TLS handshake, CERT verify (15):
* TLSv1.3 (IN), TLS handshake, Finished (20):
* TLSv1.2 (OUT), TLS header, Finished (20):
* TLSv1.3 (OUT), TLS change cipher, Change cipher spec (1):
* TLSv1.2 (OUT), TLS header, Supplemental data (23):
* TLSv1.3 (OUT), TLS handshake, Finished (20):
* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384
* ALPN, server accepted to use h2
* Server certificate:
*  subject: C=CN; ST=GD; L=SZ; O=httpbin.example.com, Inc.; CN=*.httpbin.example.com
*  start date: Jun 25 06:02:22 2023 GMT
*  expire date: Jun 24 06:02:22 2024 GMT
*  issuer: C=CN; ST=GD; L=SZ; O=httpbin.example.com, Inc.; CN=httpbin.example.com Root CA
*  SSL certificate verify result: unable to get local issuer certificate (20), continuing anyway.
* Using HTTP2, server supports multiplexing
* Connection state changed (HTTP/2 confirmed)
* Copying HTTP/2 data in stream buffer to connection buffer after upgrade: len=0
* TLSv1.2 (OUT), TLS header, Supplemental data (23):
* TLSv1.2 (OUT), TLS header, Supplemental data (23):
* TLSv1.2 (OUT), TLS header, Supplemental data (23):
* Using Stream ID: 1 (easy handle 0x55eb969bde90)
* TLSv1.2 (OUT), TLS header, Supplemental data (23):
> HEAD / HTTP/2
> Host: httpbin.example.com:32004
> user-agent: curl/7.81.0
> accept: */*
>
* TLSv1.2 (IN), TLS header, Supplemental data (23):
* TLSv1.3 (IN), TLS handshake, Newsession Ticket (4):
* TLSv1.3 (IN), TLS handshake, Newsession Ticket (4):
* old SSL session ID is stale, removing
* TLSv1.2 (IN), TLS header, Supplemental data (23):
* Connection state changed (MAX_CONCURRENT_STREAMS == 2147483647)!
* TLSv1.2 (OUT), TLS header, Supplemental data (23):
* TLSv1.2 (IN), TLS header, Supplemental data (23):
< HTTP/2 200
HTTP/2 200
< server: istio-envoy
server: istio-envoy
< date: Sun, 25 Jun 2023 08:40:26 GMT
date: Sun, 25 Jun 2023 08:40:26 GMT
< content-type: text/html; charset=utf-8
content-type: text/html; charset=utf-8
< content-length: 9593
content-length: 9593
< access-control-allow-origin: *
access-control-allow-origin: *
< access-control-allow-credentials: true
access-control-allow-credentials: true
< x-envoy-upstream-service-time: 1
x-envoy-upstream-service-time: 1

<
* Connection #0 to host httpbin.example.com left intact

```
And you can also get some debug logs from istio ingress gateway pod like:
```
2023-06-25T05:29:28.781124Z	info	envoy connection external/envoy/contrib/qat/private_key_providers/source/qat_private_key_provider.cc:388	initialized QAT private key provider	thread=27
2023-06-25T05:29:28.781149Z	debug	envoy config external/envoy/source/extensions/transport_sockets/tls/ssl_socket.cc:408	Secret is updated.	thread=27
2023-06-25T05:29:28.781491Z	debug	envoy connection external/envoy/contrib/qat/private_key_providers/source/qat.cc:134	found 64 QAT instances	thread=27
2023-06-25T05:29:28.781565Z	debug	envoy connection external/envoy/contrib/qat/private_key_providers/source/qat.cc:32	created QAT polling thread	thread=98
2023-06-25T05:29:28.781624Z	debug	envoy connection external/envoy/contrib/qat/private_key_providers/source/qat.cc:32	created QAT polling thread	thread=99
2023-06-25T05:29:28.781667Z	debug	envoy connection external/envoy/contrib/qat/private_key_providers/source/qat.cc:32	created QAT polling thread	thread=100
2023-06-25T05:29:28.781756Z	debug	envoy connection external/envoy/contrib/qat/private_key_providers/source/qat.cc:32	created QAT polling thread	thread=102
2023-06-25T05:29:28.781804Z	debug	envoy connection external/envoy/contrib/qat/private_key_providers/source/qat.cc:32	created QAT polling thread	thread=103
2023-06-25T05:29:28.781814Z	debug	envoy connection external/envoy/contrib/qat/private_key_providers/source/qat.cc:32	created QAT polling thread	thread=101
2023-06-25T05:29:28.781853Z	debug	envoy connection external/envoy/contrib/qat/private_key_providers/source/qat.cc:32	created QAT polling thread	thread=104
2023-06-25T05:29:28.781895Z	debug	envoy connection external/envoy/contrib/qat/private_key_providers/source/qat.cc:32	created QAT polling thread	thread=105
2023-06-25T05:29:28.781981Z	debug	envoy connection external/envoy/contrib/qat/private_key_providers/source/qat.cc:32	created QAT polling thread	thread=107
2023-06-25T05:29:28.782045Z	debug	envoy connection external/envoy/contrib/qat/private_key_providers/source/qat.cc:32	created QAT polling thread	thread=106
2023-06-25T05:29:28.782069Z	debug	envoy connection external/envoy/contrib/qat/private_key_providers/source/qat.cc:32	created QAT polling thread	thread=109
2023-06-25T05:29:28.782123Z	debug	envoy connection external/envoy/contrib/qat/private_key_providers/source/qat.cc:32	created QAT polling thread	thread=110
2023-06-25T05:29:28.782132Z	debug	envoy connection external/envoy/contrib/qat/private_key_providers/source/qat.cc:32	created QAT polling thread	thread=108
2023-06-25T05:29:28.782168Z	debug	envoy connection external/envoy/contrib/qat/private_key_providers/source/qat.cc:32	created QAT polling thread	thread=111
2023-06-25T05:29:28.782212Z	debug	envoy connection external/envoy/contrib/qat/private_key_providers/source/qat.cc:32	created QAT polling thread	thread=112
```




