#ifndef WALLET_H
#define WALLET_H

#include <vector>
#include <string>

class Wallet {
public:
    static std::vector<unsigned char> generatePrivateKey();
    static std::vector<unsigned char> derivePublicKey(const std::vector<unsigned char>& privkey);
    static std::string generateBech32Address(const std::vector<unsigned char>& pubkey, bool testnet=true);
};

#endif
