#include "bip39.h"
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <sstream>

std::vector<unsigned char> BIP39::mnemonicToSeed(
    const std::string& mnemonic,
    const std::string& passphrase) {

    std::string salt = "mnemonic" + passphrase;

    std::vector<unsigned char> seed(64);

    PKCS5_PBKDF2_HMAC(
        mnemonic.c_str(),
        mnemonic.size(),
        (unsigned char*)salt.c_str(),
        salt.size(),
        2048,
        EVP_sha512(),
        64,
        seed.data()
    );

    return seed;
}
