#include "wallet.h"
#include "bech32.h"
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <secp256k1.h>
#include <stdexcept>

static const unsigned char SECP256K1_ORDER[32] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
    0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,
    0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41
};

static bool isValidPrivateKey(const std::vector<unsigned char>& key) {
    if (key.size() != 32) return false;
    for (int i = 0; i < 32; i++) {
        if (key[i] < SECP256K1_ORDER[i]) return true;
        if (key[i] > SECP256K1_ORDER[i]) return false;
    }
    return false;
}

std::vector<unsigned char> Wallet::generatePrivateKey() {
    std::vector<unsigned char> key(32);
    do {
        RAND_bytes(key.data(), 32);
    } while (!isValidPrivateKey(key));
    return key;
}

std::vector<unsigned char> Wallet::derivePublicKey(const std::vector<unsigned char>& privkey) {
    secp256k1_context* ctx =
        secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, privkey.data())) {
        throw std::runtime_error("Invalid private key");
    }

    unsigned char serialized[33];
    size_t len = 33;

    secp256k1_ec_pubkey_serialize(
        ctx,
        serialized,
        &len,
        &pubkey,
        SECP256K1_EC_COMPRESSED
    );

    secp256k1_context_destroy(ctx);
    return std::vector<unsigned char>(serialized, serialized + len);
}

std::string Wallet::generateBech32Address(const std::vector<unsigned char>& pubkey, bool testnet) {

    unsigned char sha[32];
    SHA256(pubkey.data(), pubkey.size(), sha);

    unsigned char ripe[20];
    RIPEMD160(sha, 32, ripe);

    std::vector<unsigned char> program(ripe, ripe+20);

    std::string hrp = testnet ? "tb" : "bc";

    return Bech32::encode(hrp, 0, program);
}
