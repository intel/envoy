#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "envoy/config/core/v3/base.pb.h"
#include "envoy/grpc/async_client.h"
#include "envoy/grpc/async_client_manager.h"
#include "envoy/http/filter.h"
#include "envoy/http/header_map.h"
#include "envoy/http/protocol.h"
#include "envoy/network/address.h"
#include "envoy/network/connection.h"
#include "envoy/network/filter.h"
#include "envoy/service/secret/v3/sds.pb.h"
#include "envoy/tracing/http_tracer.h"
#include "envoy/upstream/cluster_manager.h"

#include "source/common/grpc/typed_async_client.h"

#include "contrib/envoy/extensions/private_key_providers/sgx/v3alpha/sgx.pb.h"

namespace Envoy {
namespace Extensions {
namespace PrivateKeyMethodProvider {
namespace Sgx {

using envoy::service::secret::v3::CsrAndQuoteRequest;
using envoy::service::secret::v3::CsrAndQuoteResponse;

using CsrAndQuoteRequestPtr = std::unique_ptr<CsrAndQuoteRequest>;
using CsrAndQuoteResponsePtr = std::unique_ptr<CsrAndQuoteResponse>;

class SgxRpcCallbacks : public Logger::Loggable<Logger::Id::grpc> {
public:
  ~SgxRpcCallbacks() = default;

  static void onReceiveMessage(std::unique_ptr<CsrAndQuoteResponse>&& response);

  void onGrpcError(Grpc::Status::GrpcStatus error);

  void onGrpcClose();
};

class SgxRpcStream {
public:
  virtual ~SgxRpcStream() = default;

  virtual void send(CsrAndQuoteRequest&& request, bool end_stream) PURE;

  virtual bool close() PURE;
};

// ---------------------------------------------------------------------------------------------------------

class SgxRpcStreamImpl : public SgxRpcStream,
                         public Grpc::AsyncStreamCallbacks<CsrAndQuoteResponse>,
                         public Logger::Loggable<Logger::Id::connection> {
public:
  SgxRpcStreamImpl(Grpc::RawAsyncClientSharedPtr async_client, SgxRpcCallbacks& callbacks);

  ~SgxRpcStreamImpl() override = default;

  // SgxRpcStream
  bool close() override;

  void send(CsrAndQuoteRequest&& request, bool end_stream) override;

  // RawAsyncStreamCallbacks
  void onCreateInitialMetadata(Http::RequestHeaderMap& metadata) override;

  void onReceiveInitialMetadata(Http::ResponseHeaderMapPtr&& metadata) override;

  void onReceiveTrailingMetadata(Http::ResponseTrailerMapPtr&& metadata) override;

  void onRemoteClose(Grpc::Status::GrpcStatus status, const std::string& message) override;

  // Grpc::AsyncStreamCallbacks
  void onReceiveMessage(CsrAndQuoteResponsePtr&& message) override;

  Grpc::AsyncStream<CsrAndQuoteRequest> start();

private:
  SgxRpcCallbacks& callbacks_;
  Grpc::AsyncClient<CsrAndQuoteRequest, CsrAndQuoteResponse> client_;
  const Protobuf::MethodDescriptor& service_method_;
  Grpc::AsyncStream<CsrAndQuoteRequest> stream_;
  bool stream_closed_ = false;
};

using GrpcClientImplPtr = std::unique_ptr<SgxRpcStreamImpl>;

} // namespace Sgx
} // namespace PrivateKeyMethodProvider
} // namespace Extensions
} // namespace Envoy
