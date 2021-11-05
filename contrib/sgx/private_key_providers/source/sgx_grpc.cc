#include "contrib/sgx/private_key_providers/source/sgx_grpc.h"

#include <fstream>
#include <iomanip>
#include <utility>

#include "envoy/config/core/v3/base.pb.h"

#include "source/common/grpc/async_client_impl.h"
#include "source/common/http/utility.h"
#include "source/common/network/utility.h"

namespace Envoy {
namespace Extensions {
namespace PrivateKeyMethodProvider {
namespace Sgx {

void SgxRpcCallbacks::onGrpcClose() {}

void SgxRpcCallbacks::onGrpcError(Grpc::Status::GrpcStatus) {}

void SgxRpcCallbacks::onReceiveMessage(std::unique_ptr<CsrAndQuoteResponse>&& response) {
  ENVOY_LOG(debug, "sgx|grpc: SgxRpcCallbacks CsrAndQuoteResponse: {}", (*response).DebugString());
  ENVOY_LOG(debug, "sgx|grpc: New Certificate has been loaded");
}

SgxRpcStreamImpl::SgxRpcStreamImpl(Grpc::RawAsyncClientSharedPtr async_client,
                                   SgxRpcCallbacks& callbacks)
    : callbacks_(callbacks), client_(std::move(async_client)),
      service_method_(*Protobuf::DescriptorPool::generated_pool()->FindMethodByName(
          "envoy.service.secret.v3.SecretDiscoveryService.SendCsrAndQuote")) {}

bool SgxRpcStreamImpl::close() {
  if (!stream_closed_) {
    ENVOY_LOG(debug, "sgx: Closing gRPC stream");
    stream_.closeStream();
    stream_closed_ = true;
    stream_.resetStream();
    return true;
  }
  return false;
}

void SgxRpcStreamImpl::send(CsrAndQuoteRequest&& request, bool end_stream) {
  ENVOY_LOG(debug, "sgx: Sending CheckRequest: {}", request.DebugString());
  stream_.sendMessage(std::move(request), end_stream);
}

void SgxRpcStreamImpl::onCreateInitialMetadata(Http::RequestHeaderMap&) {}

void SgxRpcStreamImpl::onReceiveInitialMetadata(Http::ResponseHeaderMapPtr&&) {}

void SgxRpcStreamImpl::onReceiveTrailingMetadata(Http::ResponseTrailerMapPtr&&) {}

void SgxRpcStreamImpl::onRemoteClose(Grpc::Status::GrpcStatus status, const std::string& message) {
  ENVOY_LOG(debug, "sgx: gRPC stream closed remotely with status {}: {}", status, message);
  stream_closed_ = true;
  if (status == Grpc::Status::Ok) {
    callbacks_.onGrpcClose();
  } else {
    callbacks_.onGrpcError(status);
  }
}

void SgxRpcStreamImpl::onReceiveMessage(CsrAndQuoteResponsePtr&& message) {
  ENVOY_LOG(debug, "sgx: onReceiveMessageReceived CsrAndQuoteResponse: {}", message->DebugString());
  callbacks_.onReceiveMessage(std::move(message));
}

Grpc::AsyncStream<CsrAndQuoteRequest> SgxRpcStreamImpl::start() {
  Http::AsyncClient::StreamOptions options;
  stream_ = client_.start(service_method_, *this, options);
  return stream_;
}

} // namespace Sgx
} // namespace PrivateKeyMethodProvider
} // namespace Extensions
} // namespace Envoy
