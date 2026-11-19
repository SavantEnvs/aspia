// Fuzz target: INI settings file parser and writer (base/ini_file.cc), used for the host, router
// and relay settings files. IniFile only reads from a path, so the input is written to one scratch
// file under $TMPDIR (overwritten every iteration), parsed, queried, modified and saved back.
#include <QByteArray>
#include <QString>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <unistd.h>

#include "base/ini_file.h"

namespace {

volatile size_t g_sink;
std::string g_path;

const char* kSections[] = { "General", "Router", "Update", "Relay", "" };
const char* kKeys[] = { "Port", "Address", "Enabled", "PublicKey", "Name", "Server", "" };

} // namespace

extern "C" int LLVMFuzzerInitialize(int*, char***)
{
    const char* tmp = getenv("TMPDIR");
    std::string tmpl = std::string(tmp && *tmp ? tmp : "/tmp") + "/aspia-ini-XXXXXX";
    int fd = mkstemp(tmpl.data());
    if (fd < 0)
        abort();
    close(fd);
    g_path = tmpl;
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FILE* f = fopen(g_path.c_str(), "wb");
    if (!f)
        abort();
    if (size && fwrite(data, 1, size, f) != size)
        abort();
    fclose(f);

    const QString path = QString::fromStdString(g_path);
    IniFile ini(path);
    for (const char* section : kSections)
    {
        for (const char* key : kKeys)
        {
            g_sink += static_cast<size_t>(ini.stringValue(section, key).size());
            g_sink += static_cast<size_t>(ini.binaryValue(section, key).size());
            g_sink += ini.booleanValue(section, key);
            g_sink += static_cast<size_t>(ini.int64Value(section, key));
            g_sink += static_cast<size_t>(ini.uint16Value(section, key));
        }
    }
    ini.setStringValue("General", "Name", QStringLiteral("a=b;c\\d\n"));
    ini.setBinaryValue("General", "PublicKey", QByteArray("\x00\x01\xff", 3));
    ini.removeValue("Router", "Port");
    g_sink += ini.sync();
    return 0;
}
