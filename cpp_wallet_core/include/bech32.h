#ifndef BECH32_H
#define BECH32_H

#include <string>
#include <vector>

class Bech32 {
public:
    static std::string encode(const std::string& hrp, int witver,
                              const std::vector<unsigned char>& program);
};

#endif
