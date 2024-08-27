/**************************************************************************************************
 * Copyright (c) 2024 Calypso Networks Association https://calypsonet.org/                        *
 *                                                                                                *
 * This program and the accompanying materials are made available under the                       *
 * terms of the MIT License which is available at https://opensource.org/licenses/MIT.            *
 *                                                                                                *
 * SPDX-License-Identifier: MIT                                                                   *
 **************************************************************************************************/

#pragma once

#include <memory>
#include <vector>

#include "keypop/calypso/crypto/symmetric/spi/SymmetricCryptoCardTransactionManagerSpi.hpp"

namespace keypop {
namespace calypso {
namespace crypto {
namespace symmetric {
namespace spi {

/**
 * Factory of {@link SymmetricCryptoCardTransactionManagerSpi}.
 *
 * @since 0.1.0
 */
class SymmetricCryptoCardTransactionManagerFactorySpi {
public:
    /**
     * Indicates if the "extended" mode is supported.
     *
     * @return True if the "extended" mode is supported, false otherwise.
     * @since 0.1.0
     */
    virtual bool isExtendedModeSupported() const = 0;

    /**
     * Returns the max length supported of the card APDU.
     *
     * @return A positive value.
     * @since 0.1.0
     */
    virtual int getMaxCardApduLengthSupported() const = 0;

    /**
     * Retrieves and stores the terminal challenge in the SAM image for later use.
     *
     * @throws SymmetricCryptoException If an internal error occurred.
     * @throw SymmetricCryptoIOException If an IO error occurred when processing a command.
     * @since 0.1.0
     */
    virtual void preInitTerminalSessionContext() = 0;

    /**
     * Returns a new instance of SymmetricCryptoCardTransactionManagerSpi.
     *
     * @param cardKeyDiversifier The card key diversifier to use for the coming cryptographic
     *        computations.
     * @param useExtendedMode Request the use of the extended mode if supported by the crypto
     *        service.
     * @param transactionAuditData The reference of the list where the transaction audit data are
     *        recorded.
     * @return A new instance of {@link SymmetricCryptoCardTransactionManagerSpi}.
     * @throw IllegalStateException If the extended mode is not supported.
     * @since 0.1.0
     */
    virtual std::shared_ptr<SymmetricCryptoCardTransactionManagerSpi> createCardTransactionManager(
        const std::vector<uint8_t>& cardKeyDiversifier,
        const bool useExtendedMode,
        const std::vector<std::vector<uint8_t>>& transactionAuditData)
        = 0;
};

} /* namespace spi */
} /* namespace symmetric */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace keypop */
