#include "signer.h"
#include <openssl/sha.h>
#include <secp256k1.h>

std::vector<unsigned char> doubleSHA256(
    const std::vector<unsigned char>& data) {

    unsigned char hash1[32];
    SHA256(data.data(), data.size(), hash1);

    unsigned char hash2[32];
    SHA256(hash1, 32, hash2);

    return std::vector<unsigned char>(hash2, hash2+32);
}

std::vector<unsigned char> Signer::signInput(
    const std::vector<unsigned char>& privkey,
    const std::vector<unsigned char>& sighash) {

    secp256k1_context* ctx =
        secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

    secp256k1_ecdsa_signature sig;

    secp256k1_ecdsa_sign(
        ctx,
        &sig,
        sighash.data(),
        privkey.data(),
        nullptr,
        nullptr
    );

    unsigned char output[72];
    size_t len = 72;

    secp256k1_ecdsa_signature_serialize_der(
        ctx,
        output,
        &len,
        &sig
    );

    secp256k1_context_destroy(ctx);

    return std::vector<unsigned char>(output, output+len);
}
