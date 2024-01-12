#include "contrib/qat/compression/qatzstd/compressor/source/config.h"

namespace Envoy {
namespace Extensions {
namespace Compression {
namespace Qatzstd {
namespace Compressor {

QatzstdCompressorFactory::QatzstdCompressorFactory(
    const envoy::extensions::compression::qatzstd::compressor::v3alpha::Qatzstd& qatzstd,
    Event::Dispatcher& dispatcher, Api::Api& api, ThreadLocal::SlotAllocator& tls)
    : compression_level_(
          PROTOBUF_GET_WRAPPED_OR_DEFAULT(qatzstd, compression_level, ZSTD_CLEVEL_DEFAULT)),
      enable_checksum_(qatzstd.enable_checksum()), strategy_(qatzstd.strategy()),
      chunk_size_(PROTOBUF_GET_WRAPPED_OR_DEFAULT(qatzstd, chunk_size, ZSTD_CStreamOutSize())),
      enable_qat_zstd_(qatzstd.enable_qat_zstd()),
      qat_zstd_fallback_threshold_(PROTOBUF_GET_WRAPPED_OR_DEFAULT(
          qatzstd, qat_zstd_fallback_threshold, DefaultQatZstdFallbackThreshold)),
      tls_slot_(nullptr) {
  if (qatzstd.has_dictionary()) {
    Protobuf::RepeatedPtrField<envoy::config::core::v3::DataSource> dictionaries;
    dictionaries.Add()->CopyFrom(qatzstd.dictionary());
    cdict_manager_ = std::make_unique<ZstdCDictManager>(
        dictionaries, dispatcher, api, tls, true,
        [this](const void* dict_buffer, size_t dict_size) -> ZSTD_CDict* {
          return ZSTD_createCDict(dict_buffer, dict_size, compression_level_);
        });
  }
  if (enable_qat_zstd_) {
    tls_slot_ = ThreadLocal::TypedSlot<QatzstdThreadLocal>::makeUnique(tls);
    tls_slot_->set([](Event::Dispatcher&) { return std::make_shared<QatzstdThreadLocal>(); });
  }
}

QatzstdCompressorFactory::QatzstdThreadLocal::QatzstdThreadLocal()
    : initialized_(false), sequenceProducerState_(nullptr) {}

QatzstdCompressorFactory::QatzstdThreadLocal::~QatzstdThreadLocal() {
  if (initialized_) {
    /* Free sequence producer state */
    QZSTD_freeSeqProdState(sequenceProducerState_);
    /* Stop QAT device, please call this function when
    you won't use QAT anymore or before the process exits */
    QZSTD_stopQatDevice();
  }
}

void* QatzstdCompressorFactory::QatzstdThreadLocal::GetQATSession() {
  // The session must be initialized only once in every worker thread.
  if (!initialized_) {

    int status = QZSTD_startQatDevice();
    RELEASE_ASSERT(status == QZSTD_OK, "failed to initialize hardware");
    sequenceProducerState_ = QZSTD_createSeqProdState();
    initialized_ = true;
  }

  return sequenceProducerState_;
}

Envoy::Compression::Compressor::CompressorPtr QatzstdCompressorFactory::createCompressor() {
  if (enable_qat_zstd_) {
    return std::make_unique<QatzstdCompressorImpl>(
        compression_level_, enable_checksum_, strategy_, cdict_manager_, chunk_size_,
        enable_qat_zstd_, qat_zstd_fallback_threshold_, tls_slot_->get()->GetQATSession());
  } else {
    return std::make_unique<QatzstdCompressorImpl>(compression_level_, enable_checksum_, strategy_,
                                                   cdict_manager_, chunk_size_, enable_qat_zstd_,
                                                   qat_zstd_fallback_threshold_, nullptr);
  }
}

Envoy::Compression::Compressor::CompressorFactoryPtr
QatzstdCompressorLibraryFactory::createCompressorFactoryFromProtoTyped(
    const envoy::extensions::compression::qatzstd::compressor::v3alpha::Qatzstd& proto_config,
    Server::Configuration::FactoryContext& context) {
  return std::make_unique<QatzstdCompressorFactory>(proto_config, context.mainThreadDispatcher(),
                                                    context.api(), context.threadLocal());
}

/**
 * Static registration for the zstd compressor library. @see NamedCompressorLibraryConfigFactory.
 */
REGISTER_FACTORY(QatzstdCompressorLibraryFactory,
                 Envoy::Compression::Compressor::NamedCompressorLibraryConfigFactory);

} // namespace Compressor
} // namespace Qatzstd
} // namespace Compression
} // namespace Extensions
} // namespace Envoy
