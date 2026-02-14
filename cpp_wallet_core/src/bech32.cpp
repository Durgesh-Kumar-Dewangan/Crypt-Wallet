#include "bech32.h"
#include <vector>
#include <string>
#include <stdexcept>

static const char* CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static std::vector<unsigned char> convertBits(
    const std::vector<unsigned char>& data,
    int fromBits, int toBits, bool pad=true) {

    int acc = 0;
    int bits = 0;
    std::vector<unsigned char> ret;
    int maxv = (1 << toBits) - 1;

    for (unsigned char value : data) {
        acc = (acc << fromBits) | value;
        bits += fromBits;
        while (bits >= toBits) {
            bits -= toBits;
            ret.push_back((acc >> bits) & maxv);
        }
    }

    if (pad && bits)
        ret.push_back((acc << (toBits - bits)) & maxv);

    return ret;
}

std::string Bech32::encode(const std::string& hrp, int witver,
                           const std::vector<unsigned char>& program) {

    std::vector<unsigned char> data;
    data.push_back(witver);

    auto conv = convertBits(program, 8, 5);
    data.insert(data.end(), conv.begin(), conv.end());

    std::string ret = hrp + "1";
    for (auto d : data)
        ret += CHARSET[d];

    return ret;
}
