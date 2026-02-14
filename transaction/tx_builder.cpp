#include "tx_builder.h"
#include <vector>
#include <cstdint>

static void writeUint32(std::vector<unsigned char>& buf, uint32_t val) {
    for (int i = 0; i < 4; i++)
        buf.push_back((val >> (8*i)) & 0xff);
}

static void writeUint64(std::vector<unsigned char>& buf, uint64_t val) {
    for (int i = 0; i < 8; i++)
        buf.push_back((val >> (8*i)) & 0xff);
}

std::vector<unsigned char> TransactionBuilder::buildRawTransaction(
    const std::vector<UTXO>& inputs,
    const std::vector<TxOutput>& outputs) {

    std::vector<unsigned char> tx;

    writeUint32(tx, 2);  // version
    tx.push_back(0x00);  // marker
    tx.push_back(0x01);  // flag

    tx.push_back(inputs.size());

    for (const auto& in : inputs) {

        // txid (reverse byte order required in real impl)
        for (int i = 0; i < 32; i++)
            tx.push_back(0x00); // placeholder

        writeUint32(tx, in.vout);

        tx.push_back(0x00); // empty scriptSig

        writeUint32(tx, 0xffffffff); // sequence
    }

    tx.push_back(outputs.size());

    for (const auto& out : outputs) {
        writeUint64(tx, out.amount);
        tx.push_back(out.scriptPubKey.size());
        tx.insert(tx.end(),
                  out.scriptPubKey.begin(),
                  out.scriptPubKey.end());
    }

    // Witness placeholder
    for (size_t i = 0; i < inputs.size(); i++)
        tx.push_back(0x00);

    writeUint32(tx, 0); // locktime

    return tx;
}
