#ifndef SECURE_WALLET_H
#define SECURE_WALLET_H

#include <vector>
#include <string>

class SecureWallet {
public:
    static void encryptAndSave(
        const std::vector<unsigned char>& seed,
        const std::string& password,
        const std::string& filepath
    );

    static std::vector<unsigned char> loadAndDecrypt(
        const std::string& password,
        const std::string& filepath
    );
};

#endif
