#include <iostream>

#include "keypop/calypso/crypto/symmetric/SymmetricCryptoApiProperties.hpp"

int
main()
{
    std::cout << "Keypop::Calypso::Crypto::Symmetric header-only package resolved and linked correctly (API version "
              << keypop::calypso::crypto::symmetric::SymmetricCryptoApiProperties_VERSION << ")" << std::endl;
    return 0;
}
