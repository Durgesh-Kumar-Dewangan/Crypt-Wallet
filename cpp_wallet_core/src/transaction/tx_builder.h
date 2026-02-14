#ifndef TX_BUILDER_H
#define TX_BUILDER_H

#include "utxo.h"
#include <vector>
#include <string>

struct TxOutput {
    uint64_t amount;
    std::vector<unsigned char> scriptPubKey;
};

class TransactionBuilder {
public:
    static std::vector<unsigned char> buildRawTransaction(
        const std::vector<UTXO>& inputs,
        const std::vector<TxOutput>& outputs
    );
};

#endif
