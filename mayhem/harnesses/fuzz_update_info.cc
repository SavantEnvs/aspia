// Fuzz target: update manifest parser (base/update/update_info.cc). The manifest is downloaded
// from the update server; the client and host parse it with UpdateInfo::targetVersion and
// UpdateInfo::fromManifest (arguments as in update_info_unittest.cc).
#include <QByteArray>
#include <QString>
#include <QVersionNumber>
#include <cstddef>
#include <cstdint>

#include "base/update/update_info.h"

namespace {
volatile size_t g_sink;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    const QByteArray buffer(reinterpret_cast<const char*>(data), static_cast<qsizetype>(size));

    auto target = UpdateInfo::targetVersion(buffer, QVersionNumber(2, 6, 0));
    if (target.has_value())
        g_sink += static_cast<size_t>(target->segmentCount());
    target = UpdateInfo::targetVersion(buffer, QVersionNumber(3, 0, 0));
    if (target.has_value())
        g_sink += static_cast<size_t>(target->segmentCount());

    auto info = UpdateInfo::fromManifest(buffer, QStringLiteral("host"), QStringLiteral("linux"),
                                         QStringLiteral("x86_64"), QStringLiteral("deb"));
    if (info.has_value())
        g_sink += static_cast<size_t>(info->isValid() + info->version().segmentCount() +
            info->description().size() + info->url().size() + info->sha256().size() + info->format().size());
    return 0;
}
