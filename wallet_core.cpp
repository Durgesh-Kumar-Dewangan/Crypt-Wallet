#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/rand.h>
#include <secp256k1.h>

static const char* BASE58_ALPHABET = 
"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/* ---------------- SHA256 ---------------- */
std::vector<unsigned char> sha256(const std::vector<unsigned char>& data) {
    std::vector<unsigned char> hash(SHA256_DIGEST_LENGTH);
    SHA256(data.data(), data.size(), hash.data());
    return hash;
}

/* ---------------- RIPEMD160 ---------------- */
std::vector<unsigned char> ripemd160(const std::vector<unsigned char>& data) {
    std::vector<unsigned char> hash(RIPEMD160_DIGEST_LENGTH);
    RIPEMD160(data.data(), data.size(), hash.data());
    return hash;
}

/* ---------------- Base58 Encoding ---------------- */
std::string base58Encode(const std::vector<unsigned char>& input) {
    std::vector<unsigned char> digits((input.size() * 138 / 100) + 1);
    size_t digitlen = 1;

    for (unsigned char byte : input) {
        int carry = byte;
        for (size_t i = 0; i < digitlen; ++i) {
            carry += digits[i] << 8;
            digits[i] = carry % 58;
            carry /= 58;
        }
        while (carry) {
            digits[digitlen++] = carry % 58;
            carry /= 58;
        }
    }

    std::string result;
    for (unsigned char byte : input)
        if (byte == 0) result += '1';
        else break;

    for (size_t i = 0; i < digitlen; ++i)
        result += BASE58_ALPHABET[digits[digitlen - 1 - i]];

    return result;
}

/* ---------------- Key Generation ---------------- */
std::vector<unsigned char> generatePrivateKey() {
    std::vector<unsigned char> privkey(32);
    RAND_bytes(privkey.data(), 32);
    return privkey;
}

/* ---------------- Public Key Derivation ---------------- */
std::vector<unsigned char> derivePublicKey(const std::vector<unsigned char>& privkey) {
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, privkey.data())) {
        throw std::runtime_error("Failed to create public key");
    }

    unsigned char serialized[33];
    size_t len = 33;
    secp256k1_ec_pubkey_serialize(ctx, serialized, &len, &pubkey, SECP256K1_EC_COMPRESSED);

    secp256k1_context_destroy(ctx);

    return std::vector<unsigned char>(serialized, serialized + len);
}

/* ---------------- Bitcoin Address Generation ---------------- */
std::string generateAddress(const std::vector<unsigned char>& pubkey) {

    auto sha = sha256(pubkey);
    auto ripe = ripemd160(sha);

    std::vector<unsigned char> versioned;
    versioned.push_back(0x00); // Mainnet prefix
    versioned.insert(versioned.end(), ripe.begin(), ripe.end());

    auto checksum = sha256(sha256(versioned));
    versioned.insert(versioned.end(), checksum.begin(), checksum.begin() + 4);

    return base58Encode(versioned);
}

/* ---------------- ECDSA Signing ---------------- */
std::vector<unsigned char> signMessage(
    const std::vector<unsigned char>& privkey,
    const std::vector<unsigned char>& message) {

    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

    auto hash = sha256(message);

    secp256k1_ecdsa_signature signature;
    secp256k1_ecdsa_sign(ctx, &signature, hash.data(), privkey.data(), nullptr, nullptr);

    unsigned char output[72];
    size_t outputlen = 72;
    secp256k1_ecdsa_signature_serialize_der(ctx, output, &outputlen, &signature);

    secp256k1_context_destroy(ctx);

    return std::vector<unsigned char>(output, output + outputlen);
}

/* ---------------- MAIN ---------------- */
int main() {
    auto privkey = generatePrivateKey();
    auto pubkey = derivePublicKey(privkey);
    auto address = generateAddress(pubkey);

    std::cout << "Bitcoin Address: " << address << std::endl;

    std::string msg = "Hello Blockchain";
    std::vector<unsigned char> message(msg.begin(), msg.end());
    auto signature = signMessage(privkey, message);

    std::cout << "Signature (DER): ";
    for (auto byte : signature)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    std::cout << std::endl;

    return 0;
}
