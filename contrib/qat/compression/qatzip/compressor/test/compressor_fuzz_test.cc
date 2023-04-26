#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/assert.h"
#include "source/common/stats/isolated_store_impl.h"
#include "source/extensions/compression/gzip/decompressor/zlib_decompressor_impl.h"

#include "test/mocks/server/factory_context.h"
#include "test/test_common/utility.h"

#include "contrib/qat/compression/qatzip/compressor/source/config.h"

#include "test/fuzz/fuzz_runner.h"

namespace Envoy {
namespace Extensions {
namespace Compression {
namespace Qatzip {
namespace Compressor {
namespace Fuzz {

DEFINE_FUZZER(const uint8_t* buf, size_t len) {

  FuzzedDataProvider provider(buf, len);

  NiceMock<Server::Configuration::MockFactoryContext> context_;
  QatzipCompressorLibraryFactory qatzip_compressor_library_factory_;


  Stats::IsolatedStoreImpl stats_store;
  Compression::Gzip::Decompressor::ZlibDecompressorImpl decompressor{*stats_store.rootScope(), "test", 4096, 10000};


  const uint64_t target_compression_level = provider.ConsumeIntegralInRange(1, 9);

  const std::string compression_hardware_buffer_sizes[] = {
    "DEFAULT",
    "SZ_4K",
    "SZ_8K",
    "SZ_32K",
    "SZ_64K",
    "SZ_128K",
    "SZ_512K",
  };
  const std::string target_compression_hardware_buffer_size =
      provider.PickValueInArray(compression_hardware_buffer_sizes);

  const uint64_t compression_input_size_thresholds[] = {
    1024,
    2048,
    4096,
    8192,
  };
  const uint64_t target_compression_input_size_threshold =
      provider.PickValueInArray(compression_input_size_thresholds);

  const uint64_t compression_stream_buffer_sizes[] = {
    2*1024,
    8*1024,
    32*1024,
    128*1024,
  };
  const uint64_t target_compression_stream_buffer_size =
      provider.PickValueInArray(compression_stream_buffer_sizes);

  std::string json{fmt::format(R"EOF({{
  "compression_level": {},
  "hardware_buffer_size": "{}",
  "input_size_threshold": {},
  "stream_buffer_size": {},
  "chunk_size": {}
}})EOF",
                               target_compression_level, target_compression_hardware_buffer_size,
                               target_compression_input_size_threshold, target_compression_stream_buffer_size,
                               4096)};

  envoy::extensions::compression::qatzip::compressor::v3alpha::Qatzip qatzip_config;
  TestUtility::loadFromJson(json, qatzip_config);
  Envoy::Compression::Compressor::CompressorFactoryPtr qatzip_compressor_factory =
      qatzip_compressor_library_factory_.createCompressorFactoryFromProto(qatzip_config, context_);
  Envoy::Compression::Compressor::CompressorPtr compressor = 
      qatzip_compressor_factory->createCompressor();
  decompressor.init(31);

  bool provider_empty = provider.remaining_bytes() == 0;
  Buffer::OwnedImpl full_input;
  Buffer::OwnedImpl full_output;
  while (!provider_empty) {
    const std::string next_data = provider.ConsumeRandomLengthString(provider.remaining_bytes());
    ENVOY_LOG_MISC(debug, "Processing {} bytes", next_data.size());
    full_input.add(next_data);
    Buffer::OwnedImpl buffer{next_data.data(), next_data.size()};
    provider_empty = provider.remaining_bytes() == 0;
    compressor->compress(buffer, provider_empty ? Envoy::Compression::Compressor::State::Finish
                                               : Envoy::Compression::Compressor::State::Flush);
    decompressor.decompress(buffer, full_output);
  }

  RELEASE_ASSERT(full_input.toString().size() == full_output.toString().size(), "");
  RELEASE_ASSERT(full_input.toString() == full_output.toString(), "");

}

} // namespace Fuzz
} // namespace Compressor
} // namespace Qatzip
} // namespace Compression
} // namespace Extensions
} // namespace Envoy
