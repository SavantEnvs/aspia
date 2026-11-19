// Fuzz target: fixed-layout hardware blob parsers sent host -> client in system info:
// EDID (base/edid.cc) and ATA IDENTIFY / ATA SMART / NVMe SMART (base/drive_smart.cc).
// The first input byte selects the parser, the rest is the blob; all getters are called.
#include <QByteArray>
#include <cstddef>
#include <cstdint>
#include <string>

#include "base/drive_smart.h"
#include "base/edid.h"

namespace {
volatile size_t g_sink;
template <typename T> void sink(const T& v) { g_sink += sizeof(v); }
void sink(const std::string& v) { g_sink += v.size(); }
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 1)
        return -1;
    const uint8_t selector = data[0] % 4;
    const QByteArray buffer(reinterpret_cast<const char*>(data + 1), static_cast<qsizetype>(size - 1));

    switch (selector)
    {
        case 0:
        {
            Edid edid(buffer);
            if (!edid.isValid())
                break;
            sink(edid.manufacturerName()); sink(edid.monitorName()); sink(edid.monitorId());
            sink(edid.serialNumber()); sink(edid.weekOfManufacture()); sink(edid.yearOfManufacture());
            sink(edid.edidVersion()); sink(edid.edidRevision()); sink(edid.maxHorizontalImageSize());
            sink(edid.maxVerticalImageSize()); sink(edid.horizontalResolution());
            sink(edid.verticalResolution()); sink(edid.gamma()); sink(edid.featureSupport());
            sink(edid.minVerticalRate()); sink(edid.maxVerticalRate()); sink(edid.minHorizontalRate());
            sink(edid.maxHorizontalRate()); sink(edid.pixelClock()); sink(edid.maxSupportedPixelClock());
            sink(edid.inputSignalType()); sink(edid.estabilishedTimings1());
            sink(edid.estabilishedTimings2()); sink(edid.manufacturersTimings());
            const int count = edid.standardTimingsCount();
            for (int i = 0; i < count; ++i)
            {
                int w = 0, h = 0, f = 0;
                if (edid.standardTimings(i, &w, &h, &f))
                    sink(w + h + f);
            }
            break;
        }
        case 1:
        {
            AtaIdentify identify(buffer);
            if (!identify.isValid())
                break;
            sink(identify.model()); sink(identify.serialNumber()); sink(identify.firmwareRevision());
            sink(identify.rotationRate()); sink(identify.isSolidState()); sink(identify.bufferSize());
            sink(identify.isRemovable()); sink(identify.isSmartSupported()); sink(identify.isSmartEnabled());
            break;
        }
        case 2:
        {
            // Attributes and thresholds sectors: split the blob in half.
            const qsizetype half = buffer.size() / 2;
            AtaSmart smart(buffer.left(half), buffer.mid(half));
            if (!smart.isValid())
                break;
            for (const auto& a : smart.attributes())
                sink(a.id + a.status_flags + a.value + a.worst_value + a.threshold + a.raw);
            break;
        }
        default:
        {
            NvmeSmart smart(buffer);
            if (!smart.isValid())
                break;
            sink(smart.healthInfo());
            break;
        }
    }
    return 0;
}
