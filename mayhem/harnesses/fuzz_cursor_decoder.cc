// Fuzz target: remote cursor shape decoder (base/codec/cursor_decoder.cc). The host sends
// proto::cursor::Shape messages to the client; the client keeps one CursorDecoder per session
// (cursor cache + zstd stream state), so the input is a sequence of length-prefixed Shape messages
// (mayhem/harnesses/framing.h) fed to one fresh decoder per input.
#include <cstddef>
#include <cstdint>

#include "base/codec/cursor_decoder.h"
#include "base/desktop/mouse_cursor.h"
#include "framing.h"
#include "proto/desktop_cursor.h"

namespace {
volatile size_t g_sink;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    CursorDecoder decoder;
    for (const QByteArray& message : splitMessages(data, size))
    {
        proto::cursor::Shape shape;
        if (!shape.ParseFromArray(message.data(), static_cast<int>(message.size())))
            continue;
        std::shared_ptr<MouseCursor> cursor = decoder.decode(shape);
        if (cursor)
            g_sink += static_cast<size_t>(cursor->width() + cursor->height());
    }
    return 0;
}
