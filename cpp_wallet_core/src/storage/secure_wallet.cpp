#include "secure_wallet.h"
#include <sodium.h>
#include <openssl/evp.h>
#include <fstream>
#include <stdexcept>
#include <cstring>

static const unsigned char MAGIC[4] = {'N','C','B','W'};
static const unsigned char VERSION = 1;

static void deriveKey(
    const std::string& password,
    const unsigned char* salt,
    unsigned char* key) {

    if (crypto_pwhash(
            key,
            32,
            password.c_str(),
            password.length(),
            salt,
            crypto_pwhash_OPSLIMIT_MODERATE,
            crypto_pwhash_MEMLIMIT_MODERATE,
            crypto_pwhash_ALG_ARGON2ID13) != 0) {

        throw std::runtime_error("Argon2 key derivation failed");
    }
}

void SecureWallet::encryptAndSave(
    const std::vector<unsigned char>& seed,
    const std::string& password,
    const std::string& filepath) {

    if (sodium_init() < 0)
        throw std::runtime_error("libsodium init failed");

    unsigned char salt[16];
    randombytes_buf(salt, sizeof(salt));

    unsigned char key[32];
    deriveKey(password, salt, key);

    unsigned char nonce[12];
    randombytes_buf(nonce, sizeof(nonce));

    std::vector<unsigned char> ciphertext(seed.size());
    unsigned char tag[16];

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(nonce), nullptr);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, nonce);

    int len;
    EVP_EncryptUpdate(ctx,
                      ciphertext.data(),
                      &len,
                      seed.data(),
                      seed.size());

    EVP_EncryptFinal_ex(ctx, nullptr, &len);
    EVP_CIPHER_CTX_ctrl(ctx,
                        EVP_CTRL_GCM_GET_TAG,
                        sizeof(tag),
                        tag);

    EVP_CIPHER_CTX_free(ctx);

    std::ofstream file(filepath, std::ios::binary);
    file.write((char*)MAGIC, 4);
    file.write((char*)&VERSION, 1);
    file.write((char*)salt, 16);
    file.write((char*)nonce, 12);
    file.write((char*)tag, 16);
    file.write((char*)ciphertext.data(), ciphertext.size());
    file.close();

    sodium_memzero(key, sizeof(key));
}

std::vector<unsigned char> SecureWallet::loadAndDecrypt(
    const std::string& password,
    const std::string& filepath) {

    if (sodium_init() < 0)
        throw std::runtime_error("libsodium init failed");

    std::ifstream file(filepath, std::ios::binary);
    if (!file)
        throw std::runtime_error("Wallet file not found");

    unsigned char magic[4];
    file.read((char*)magic, 4);

    if (memcmp(magic, MAGIC, 4) != 0)
        throw std::runtime_error("Invalid wallet file");

    unsigned char version;
    file.read((char*)&version, 1);

    unsigned char salt[16];
    file.read((char*)salt, 16);

    unsigned char nonce[12];
    file.read((char*)nonce, 12);

    unsigned char tag[16];
    file.read((char*)tag, 16);

    std::vector<unsigned char> ciphertext(
        (std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>());

    file.close();

    unsigned char key[32];
    deriveKey(password, salt, key);

    std::vector<unsigned char> plaintext(ciphertext.size());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(nonce), nullptr);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, nonce);

    int len;
    EVP_DecryptUpdate(ctx,
                      plaintext.data(),
                      &len,
                      ciphertext.data(),
                      ciphertext.size());

    EVP_CIPHER_CTX_ctrl(ctx,
                        EVP_CTRL_GCM_SET_TAG,
                        sizeof(tag),
                        tag);

    int ret = EVP_DecryptFinal_ex(ctx, nullptr, &len);
    EVP_CIPHER_CTX_free(ctx);

    sodium_memzero(key, sizeof(key));

    if (ret <= 0)
        throw std::runtime_error("Wrong password or corrupted file");

    return plaintext;
}
