#include <iostream>
#include "wallet.h"

int main() {

    auto priv = Wallet::generatePrivateKey();
    auto pub = Wallet::derivePublicKey(priv);
    auto addr = Wallet::generateBech32Address(pub, true);

    std::cout << "Testnet Address: " << addr << std::endl;

    return 0;
}
