#include "bip32.h"
#include <openssl/hmac.h>

std::pair<std::vector<unsigned char>, std::vector<unsigned char>>
BIP32::masterKeyFromSeed(const std::vector<unsigned char>& seed) {

    unsigned char I[64];
    unsigned int len = 64;

    HMAC(EVP_sha512(),
         "Bitcoin seed", 12,
         seed.data(), seed.size(),
         I, &len);

    std::vector<unsigned char> priv(I, I+32);
    std::vector<unsigned char> chain(I+32, I+64);

    return {priv, chain};
}
