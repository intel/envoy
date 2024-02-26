#include "source/common/common/assert.h"
#include "source/common/stats/isolated_store_impl.h"

#include "test/mocks/server/factory_context.h"
#include "test/test_common/utility.h"

#include "contrib/sgx/private_key_providers/source/config.h"

#include "test/fuzz/fuzz_runner.h"

namespace Envoy {
namespace Extensions {
namespace PrivateKeyMethodProvider {
namespace Sgx {
namespace Fuzz {

DEFINE_FUZZER(const uint8_t* buf, size_t len) {

  FuzzedDataProvider provider(buf, len);

  NiceMock<Server::Configuration::MockTransportSocketFactoryContext> context_;
  SgxPrivateKeyMethodFactory sgx_private_key_method_factory_;

  const std::string token_label = std::string(reinterpret_cast<const char*>(buf));

  std::string yaml = fmt::format(R"EOF(
  provider_name: sgx
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.private_key_providers.sgx.v3alpha.SgxPrivateKeyMethodConfig
    sgx_library: "/home/istio-proxy/sgx/lib/libp11sgx.so"
    key_label: "envoy1"
    usr_pin: "1234"
    so_pin: "1234"
    token_label: {}
    key_type: "rsa"
)EOF",
                                 token_label);

  //   envoy::extensions::transport_sockets::tls::v3::PrivateKeyProvider sgx_config;

  envoy::extensions::transport_sockets::tls::v3::PrivateKeyProvider sgx_private_key_provider_config;
  TestUtility::loadFromYaml(yaml, sgx_private_key_provider_config);

  Envoy::Ssl::PrivateKeyMethodProviderSharedPtr sgx_private_key_provider_factory =
      sgx_private_key_method_factory_.createPrivateKeyMethodProviderInstance(sgx_private_key_provider_config, context_);
  Ssl::BoringSslPrivateKeyMethodSharedPtr method =
      sgx_private_key_provider_factory->getBoringSslPrivateKeyMethod();
  RELEASE_ASSERT(method != nullptr, "");
}

} // namespace Fuzz
} // namespace Sgx
} // namespace PrivateKeyMethodProvider
} // namespace Extensions
} // namespace Envoy
