#include "utxo.h"
#include <vector>
#include <stdexcept>

std::vector<UTXO> selectUTXOs(
    const std::vector<UTXO>& utxos,
    uint64_t targetAmount,
    uint64_t fee,
    uint64_t& totalSelected) {

    std::vector<UTXO> selected;
    totalSelected = 0;

    for (const auto& utxo : utxos) {
        selected.push_back(utxo);
        totalSelected += utxo.amount;

        if (totalSelected >= targetAmount + fee)
            return selected;
    }

    throw std::runtime_error("Insufficient funds");
}
