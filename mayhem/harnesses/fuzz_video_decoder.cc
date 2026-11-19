// Fuzz target: remote screen video decoder (base/codec/video_decoder.cc, video_decoder_vpx.cc:
// frame size / rect handling, libvpx decode into the YUV view). The host streams
// proto::video::Packet messages; the client keeps one decoder per session. The first input byte
// selects VP8 or VP9; the rest is a sequence of length-prefixed Packet messages
// (mayhem/harnesses/framing.h) decoded by one decoder.
#include <cstddef>
#include <cstdint>

#include "base/codec/video_decoder.h"
#include "framing.h"
#include "proto/desktop_video.h"

namespace {
volatile size_t g_sink;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 1)
        return -1;
    const proto::video::Encoding encoding =
        (data[0] & 1) ? proto::video::ENCODING_VP9 : proto::video::ENCODING_VP8;
    std::unique_ptr<VideoDecoder> decoder = VideoDecoder::create(encoding);
    if (!decoder)
        return 0;

    for (const QByteArray& message : splitMessages(data + 1, size - 1, 16))
    {
        proto::video::Packet packet;
        if (!packet.ParseFromArray(message.data(), static_cast<int>(message.size())))
            continue;
        if (decoder->decode(packet) == VideoDecoder::Result::SUCCESS)
        {
            const VideoDecoder::YuvView& frame = decoder->frame();
            if (frame.isValid())
            {
                const int rows = frame.size().height();
                const int stride = frame.planeStride(0);
                // Touch the first and last row of the Y plane, as the renderer would.
                if (rows > 0 && stride > 0)
                    g_sink += frame.planeData(0)[0] + frame.planeData(0)[(rows - 1) * stride];
            }
        }
    }
    return 0;
}
