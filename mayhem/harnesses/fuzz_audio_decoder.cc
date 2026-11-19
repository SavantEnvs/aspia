// Fuzz target: remote audio decoder (base/codec/audio_decoder.cc: resetForPacket with the
// packet's sampling rate / channel layout, Opus decode, resampler). The host streams
// proto::audio::Packet messages; the client keeps one AudioDecoder per session, so the input is a
// sequence of length-prefixed Packet messages (mayhem/harnesses/framing.h) for one decoder.
#include <cstddef>
#include <cstdint>

#include "base/codec/audio_decoder.h"
#include "framing.h"
#include "proto/desktop_audio.h"

namespace {
volatile size_t g_sink;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    AudioDecoder decoder;
    for (const QByteArray& message : splitMessages(data, size, 32))
    {
        proto::audio::Packet packet;
        if (!packet.ParseFromArray(message.data(), static_cast<int>(message.size())))
            continue;
        std::unique_ptr<proto::audio::Packet> decoded = decoder.decode(packet);
        if (decoded)
        {
            for (int i = 0; i < decoded->data_size(); ++i)
                g_sink += decoded->data(i).size();
        }
    }
    return 0;
}
