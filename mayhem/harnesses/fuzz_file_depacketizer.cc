// Fuzz target: the file-upload writer (common/file_depacketizer.cc). When a client uploads a file,
// FileRequestHandler::doPacket (common/file_request_handler.cc) hands each proto::file_transfer::Packet
// the peer sends to FileDepacketizer::writeNextPacket, which checks the FIRST/LAST flags, the
// declared file size against the data received, and seeks and writes the file.
//
// The input is a sequence of length-prefixed messages (mayhem/harnesses/framing.h), each parsed as
// a Packet. Like doPacket, the harness drops the depacketizer once writeNextPacket fails or a
// LAST_PACKET arrives. One fresh depacketizer per input writes one scratch file in a mkdtemp()
// directory under $TMPDIR, created with overwrite=true (truncated) each input and removed afterwards,
// so no state is carried from one input to the next. The file can only grow by the input's data.
#include <QByteArray>
#include <QFile>
#include <QString>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <string>

#include "common/file_depacketizer.h"
#include "framing.h"
#include "proto/file_transfer.h"

namespace {

QString* g_path = nullptr;
volatile size_t g_sink;

} // namespace

extern "C" int LLVMFuzzerInitialize(int*, char***)
{
    const char* tmp = getenv("TMPDIR");
    std::string dir = std::string(tmp && *tmp ? tmp : "/tmp") + "/aspia-depacket-XXXXXX";
    if (!mkdtemp(dir.data()))
        abort();
    g_path = new QString(QString::fromStdString(dir + "/upload.bin"));
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    std::unique_ptr<FileDepacketizer> depacketizer = FileDepacketizer::create(*g_path, true);
    if (!depacketizer)
        abort();

    for (const QByteArray& message : splitMessages(data, size, 32))
    {
        proto::file_transfer::Packet packet;
        if (!packet.ParseFromArray(message.constData(), static_cast<int>(message.size())))
            break;

        const bool ok = depacketizer->writeNextPacket(packet);
        g_sink += ok;
        if (!ok || (packet.flags() & proto::file_transfer::Packet::LAST_PACKET))
            break;
    }
    depacketizer.reset();
    QFile::remove(*g_path);
    return 0;
}
