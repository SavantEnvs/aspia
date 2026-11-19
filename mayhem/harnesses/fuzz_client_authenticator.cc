// Fuzz target: client side of aspia's key exchange (base/peer/client_authenticator.cc,
// authenticator.cc): ServerHello, SRP ServerKeyExchange (group parameters, salt and B from a
// possibly malicious host or router) and SessionChallenge parsing. The client runs this on bytes
// from whatever server it connects to, before authenticating it.
//
// Setup mirrors router/loopback_channel.h (SRP user "user"/"password"). The first input byte picks
// SRP or anonymous identification (anonymous uses a fixed server public key); the rest is a
// sequence of length-prefixed messages (mayhem/harnesses/framing.h) delivered to
// Authenticator::onIncomingMessage; one fresh authenticator per input.
#include <QByteArray>
#include <QCoreApplication>
#include <cstddef>
#include <cstdint>

#include "base/crypto/secure_string.h"
#include "base/peer/client_authenticator.h"
#include "framing.h"
#include "proto/key_exchange.h"

namespace {
QCoreApplication* g_app = nullptr;
volatile size_t g_sink;
} // namespace

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv)
{
    g_app = new QCoreApplication(*argc, *argv);
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 1)
        return -1;

    static const unsigned char kPublicKey[32] = {
        0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a,
        0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a };

    ClientAuthenticator authenticator;
    if (data[0] & 1)
    {
        authenticator.setIdentify(proto::key_exchange::IDENTIFY_ANONYMOUS);
        authenticator.setPeerPublicKey(QByteArray(reinterpret_cast<const char*>(kPublicKey), sizeof(kPublicKey)));
    }
    else
    {
        authenticator.setIdentify(proto::key_exchange::IDENTIFY_SRP);
        authenticator.setUserName(QStringLiteral("user"));
        authenticator.setPassword(SecureString(QStringLiteral("password")));
    }
    authenticator.setSessionType(1);

    QObject::connect(&authenticator, &Authenticator::sig_outgoingMessage,
                     [](const QByteArray& message, bool) { g_sink += static_cast<size_t>(message.size()); });

    authenticator.start();
    for (const QByteArray& message : splitMessages(data + 1, size - 1, 16))
    {
        if (authenticator.state() != Authenticator::State::PENDING)
            break;
        authenticator.onIncomingMessage(message);
    }
    g_sink += static_cast<size_t>(authenticator.state());
    return 0;
}
