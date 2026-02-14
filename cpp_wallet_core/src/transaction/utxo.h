#ifndef UTXO_H
#define UTXO_H

#include <string>
#include <vector>

struct UTXO {
    std::string txid;
    uint32_t vout;
    uint64_t amount;        // in satoshis
    std::string scriptPubKey;
};

#endif
