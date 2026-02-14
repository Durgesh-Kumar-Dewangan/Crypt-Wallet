#ifndef SIGNER_H
#define SIGNER_H

#include "utxo.h"
#include <vector>

class Signer {
public:
    static std::vector<unsigned char> signInput(
        const std::vector<unsigned char>& privkey,
        const std::vector<unsigned char>& sighash
    );
};

#endif
