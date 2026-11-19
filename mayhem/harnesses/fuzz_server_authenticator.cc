// Fuzz target: server side of aspia's pre-authentication key exchange
// (base/peer/server_authenticator.cc, authenticator.cc): ClientHello, Identify, SRP
// ClientKeyExchange and SessionResponse parsing, SRP math, X25519 key agreement. Every host and
// router runs this on bytes from unauthenticated network peers.
//
// Setup mirrors router/loopback_channel.h: one SRP user ("user"/"password"), a fixed X25519 private
// key and anonymous access enabled for every session type. The input is a sequence of
// length-prefixed messages (mayhem/harnesses/framing.h), each delivered to
// Authenticator::onIncomingMessage as the channel would; one fresh authenticator per input.
// The server's own nonces come from the system RNG, so only paths past a correctly encrypted
// client message depend on anything but the input (the fuzzer cannot reach those anyway).
#include <QByteArray>
#include <QCoreApplication>
#include <cstddef>
#include <cstdint>

#include "base/crypto/secure_byte_array.h"
#include "base/crypto/secure_string.h"
#include "base/peer/server_authenticator.h"
#include "base/peer/user.h"
#include "base/peer/user_list.h"
#include "base/shared_pointer.h"
#include "framing.h"

namespace {

class SingleUserList final : public UserList
{
public:
    explicit SingleUserList(const User& user) : user_(user) {}

    User find(const QString& username) const final
    {
        if (username.compare(user_.name, Qt::CaseInsensitive) != 0)
            return User::kInvalidUser;
        return user_;
    }

    QByteArray seedKey() const final { return seed_key_; }
    void setSeedKey(const QByteArray& seed_key) final { seed_key_ = seed_key; }

private:
    const User user_;
    QByteArray seed_key_ { "seed-key-for-fuzzing" };
};

QCoreApplication* g_app = nullptr;
User* g_user = nullptr;
volatile size_t g_sink;

} // namespace

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv)
{
    g_app = new QCoreApplication(*argc, *argv);
    g_user = new User(User::create(QStringLiteral("user"), SecureString(QStringLiteral("password"))));
    g_user->sessions = 0xFFFFFFFF;
    g_user->flags = User::ENABLED;
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    static const char kPrivateKey[32] = {
        0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x07, 0x18, 0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x0f,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x08, 0x19, 0x2a, 0x3b, 0x4c, 0x5d, 0x6e, 0x7f, 0x40 };

    ServerAuthenticator authenticator;
    authenticator.setUserList(SharedPointer<UserList>(new SingleUserList(*g_user)));
    if (!authenticator.setPrivateKey(SecureByteArray(QByteArray(kPrivateKey, sizeof(kPrivateKey)))))
        abort();
    if (!authenticator.setAnonymousAccess(ServerAuthenticator::AnonymousAccess::ENABLE, 0xFFFFFFFF))
        abort();

    QObject::connect(&authenticator, &Authenticator::sig_outgoingMessage,
                     [](const QByteArray& message, bool) { g_sink += static_cast<size_t>(message.size()); });

    authenticator.start();
    for (const QByteArray& message : splitMessages(data, size, 16))
    {
        if (authenticator.state() != Authenticator::State::PENDING)
            break;
        authenticator.onIncomingMessage(message);
    }
    g_sink += static_cast<size_t>(authenticator.state());
    return 0;
}
