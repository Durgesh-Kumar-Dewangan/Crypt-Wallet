cmake_minimum_required(VERSION 3.16)
project(CPPWalletCore)

set(CMAKE_CXX_STANDARD 17)

find_package(OpenSSL REQUIRED)
find_library(SECP256K1_LIB secp256k1 REQUIRED)

include_directories(include)

add_executable(wallet
    main.cpp
    src/wallet.cpp
    src/bip39.cpp
    src/bip32.cpp
    src/bech32.cpp
)

target_link_libraries(wallet
    OpenSSL::Crypto
    ${SECP256K1_LIB}
)
