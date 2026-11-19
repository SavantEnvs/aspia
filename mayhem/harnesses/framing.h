// Splits a fuzz input into a sequence of messages, the way aspia's channels deliver them: each
// message is a 2-byte little-endian length followed by that many bytes (a short tail is the last
// message). Used by the harnesses that feed a stream of protobuf messages into one stateful decoder.
#ifndef MAYHEM_HARNESSES_FRAMING_H
#define MAYHEM_HARNESSES_FRAMING_H

#include <QByteArray>
#include <QList>
#include <cstddef>
#include <cstdint>

inline QList<QByteArray> splitMessages(const uint8_t* data, size_t size, int max_messages = 64)
{
    QList<QByteArray> out;
    size_t pos = 0;
    while (pos + 2 <= size && out.size() < max_messages)
    {
        size_t len = static_cast<size_t>(data[pos]) | (static_cast<size_t>(data[pos + 1]) << 8);
        pos += 2;
        if (len > size - pos)
            len = size - pos;
        out.append(QByteArray(reinterpret_cast<const char*>(data + pos), static_cast<qsizetype>(len)));
        pos += len;
    }
    return out;
}

#endif // MAYHEM_HARNESSES_FRAMING_H
