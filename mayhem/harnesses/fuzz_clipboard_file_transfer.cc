// Fuzz target: clipboard file transfer between client and host (common/clipboard_file_transfer.cc).
// Both the desktop client (client/desktop/desktop/desktop_window.cc) and the host's user IPC worker
// (host/workers/user_ipc_worker.cc) hand every proto::file::Message the peer sends on the clipboard
// file channel straight to ClipboardFileTransfer::onIncomingMessage: Request (open a local file and
// stream it back in 256 KB chunks over a sliding window, or an ack for an in-flight transfer), Data
// (an incoming chunk, acknowledged back), Cancel and Error.
//
// The input is a sequence of length-prefixed messages (mayhem/harnesses/framing.h), delivered to one
// fresh ClipboardFileTransfer per input. Its local file list (the files this side offered on the
// clipboard) is fixed: a multi-chunk file, a small file, an empty file, a directory and a missing
// path, all created once under a mkdtemp() directory in $TMPDIR and only ever read afterwards, so
// no state is carried from one input to the next.
#include <QByteArray>
#include <QCoreApplication>
#include <QVector>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <string>
#include <sys/stat.h>

#include "common/clipboard_file_transfer.h"
#include "framing.h"

namespace {

QCoreApplication* g_app = nullptr;
QVector<LocalFileEntry>* g_files = nullptr;
volatile size_t g_sink;

void writeFile(const std::string& path, size_t size)
{
    FILE* f = fopen(path.c_str(), "wb");
    if (!f)
        abort();
    for (size_t i = 0; i < size; ++i)
        fputc(static_cast<int>((i * 131u + 7u) & 0xFF), f);
    fclose(f);
}

LocalFileEntry entry(const std::string& path, bool is_dir, qint64 size)
{
    LocalFileEntry e;
    e.path = QString::fromStdString(path);
    e.is_dir = is_dir;
    e.file_size = size;
    return e;
}

} // namespace

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv)
{
    g_app = new QCoreApplication(*argc, *argv);

    const char* tmp = getenv("TMPDIR");
    std::string dir = std::string(tmp && *tmp ? tmp : "/tmp") + "/aspia-clipfile-XXXXXX";
    if (!mkdtemp(dir.data()))
        abort();

    const size_t kBig = 300 * 1024; // two 256 KB chunks: exercises the window and the acks
    writeFile(dir + "/big.bin", kBig);
    writeFile(dir + "/small.txt", 5);
    writeFile(dir + "/empty", 0);
    if (mkdir((dir + "/subdir").c_str(), 0700) != 0)
        abort();

    g_files = new QVector<LocalFileEntry>();
    g_files->append(entry(dir + "/big.bin", false, kBig));
    g_files->append(entry(dir + "/small.txt", false, 5));
    g_files->append(entry(dir + "/empty", false, 0));
    g_files->append(entry(dir + "/subdir", true, 0));
    g_files->append(entry(dir + "/missing", false, 1));
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // Heap-allocated: the object carries a 256 KB read buffer.
    auto transfer = std::make_unique<ClipboardFileTransfer>();
    transfer->setLocalFileList(*g_files);

    QObject::connect(transfer.get(), &ClipboardFileTransfer::sig_sendMessage,
                     [](const QByteArray& message) { g_sink += static_cast<size_t>(message.size()); });
    QObject::connect(transfer.get(), &ClipboardFileTransfer::sig_fileDataChunk,
                     [](int index, const QByteArray& chunk, bool is_last)
                     { g_sink += static_cast<size_t>(index) + static_cast<size_t>(chunk.size()) + is_last; });

    for (const QByteArray& message : splitMessages(data, size, 16))
        transfer->onIncomingMessage(message);
    return 0;
}
