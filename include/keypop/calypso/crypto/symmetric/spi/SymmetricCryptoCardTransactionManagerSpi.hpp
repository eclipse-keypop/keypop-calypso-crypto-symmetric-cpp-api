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

#include "keypop/calypso/crypto/symmetric/SvCommandSecurityDataApi.hpp"
#include "keypop/calypso/crypto/symmetric/SymmetricCryptoException.hpp"
#include "keypop/calypso/crypto/symmetric/SymmetricCryptoIOException.hpp"

namespace keypop {
namespace calypso {
namespace crypto {
namespace symmetric {
namespace spi {

/**
 * Calypso card symmetric key cryptography service.
 *
 * <p>It defines the API needed by a terminal to perform the cryptographic operations required by a
 * Calypso card when using symmetric keys.
 *
 * <p>An instance of this interface can be obtained via the method {@link
 * SymmetricCryptoCardTransactionManagerFactorySpi#createCardTransactionManager(byte[], boolean,
 * List)}.
 *
 * @since 0.1.0
 */
class SymmetricCryptoCardTransactionManagerSpi {
public:
    /**
     * Initializes the crypto service context for operating a Secure Session with a card and gets
     * the terminal challenge.
     *
     * @return The terminal challenge.
     * @throw SymmetricCryptoException If an internal error occurred.
     * @throw SymmetricCryptoIOException If an IO error occurred when processing a command.
     * @since 0.1.0
     */
    virtual std::vector<uint8_t>& initTerminalSecureSessionContext() = 0;

    /**
     * Stores the data needed to initialize the session MAC computation for a Secure Session.
     *
     * @param openSecureSessionDataOut The data out from the card Open Secure Session command.
     * @param kif The card KIF.
     * @param kvc The card KVC.
     * @throw SymmetricCryptoException If an internal error occurred.
     * @throw SymmetricCryptoIOException If an IO error occurred when processing a command.
     * @since 0.1.0
     */
    virtual void initTerminalSessionMac(
        const std::vector<uint8_t>& openSecureSessionDataOut, const uint8_t kif, const uint8_t kvc)
        = 0;

    /**
     * Updates the digest computation with data sent or received from the card.
     *
     * <p>Returns encrypted/decrypted data when the encryption is active.
     *
     * @param cardApdu A byte array containing either the input or output data of a card command
     *        APDU.
     * @return null if the encryption is not activate, either the ciphered or deciphered command
     *         data if the encryption is active.
     * @throw SymmetricCryptoException If an internal error occurred.
     * @throw SymmetricCryptoIOException If an IO error occurred when processing a command.
     * @since 0.1.0
     */
    virtual const std::vector<uint8_t>&
    updateTerminalSessionMac(const std::vector<uint8_t>& cardApdu)
        = 0;

    /**
     * Finalizes the digest computation and returns the terminal part of the session MAC.
     *
     * @return A byte array containing the terminal session MAC.
     * @throw SymmetricCryptoException If an internal error occurred.
     * @throw SymmetricCryptoIOException If an IO error occurred when processing a command.
     * @since 0.1.0
     */
    virtual const std::vector<uint8_t>& finalizeTerminalSessionMac() = 0;

    /**
     * Generates the terminal part of the session MAC used for an early mutual authentication.
     *
     * @return A byte array containing the terminal session MAC.
     * @throw SymmetricCryptoException If an internal error occurred.
     * @throw SymmetricCryptoIOException If an IO error occurred when processing a command.
     * @since 0.1.0
     */
    virtual const std::vector<uint8_t>& generateTerminalSessionMac() = 0;

    /**
     * Activates the encryption/decryption of the data sent/received during the secure session.
     *
     * @throw SymmetricCryptoException If an internal error occurred.
     * @throw SymmetricCryptoIOException If an IO error occurred when processing a command.
     * @since 0.1.0
     */
    virtual void activateEncryption() = 0;

    /**
     * Deactivates the encryption/decryption of the data sent/received during the secure session.
     *
     * @throw SymmetricCryptoException If an internal error occurred.
     * @throw SymmetricCryptoIOException If an IO error occurred when processing a command.
     * @since 0.1.0
     */
    virtual void deactivateEncryption() = 0;

    /**
     * Verifies the card part of the session MAC finalizing the mutual authentication process.
     *
     * @param cardSessionMac A byte array containing the card session MAC.
     * @return true if the card session MAC is validated.
     * @throw SymmetricCryptoException If an internal error occurred.
     * @throw SymmetricCryptoIOException If an IO error occurred when processing a command.
     * @since 0.1.0
     */
    virtual bool isCardSessionMacValid(const std::vector<uint8_t>& cardSessionMac) = 0;

    /**
     * Computes the needed data to operate SV card commands.
     *
     * @param data The data involved in the preparation of an SV Reload/Debit/Undebit command.
     * @throw SymmetricCryptoException If an internal error occurred.
     * @throw SymmetricCryptoIOException If an IO error occurred when processing a command.
     * @since 0.1.0
     */
    virtual void computeSvCommandSecurityData(const std::shared_ptr<SvCommandSecurityDataApi> data)
        = 0;

    /**
     * Verifies the SV card MAC.
     *
     * @param cardSvMac A byte array containing the card SV MAC.
     * @return true if the card SV MAC is validated.
     * @throw SymmetricCryptoException If an internal error occurred.
     * @throw SymmetricCryptoIOException If an IO error occurred when processing a command.
     * @since 0.1.0
     */
    virtual bool isCardSvMacValid(const std::vector<uint8_t>& cardSvMac) = 0;

    /**
     * Computes a block of encrypted data to be sent to the card for an enciphered PIN presentation.
     *
     * <p>Note: the {@code kif} and {@code kvc} parameters are ignored when PIN verification is
     * performed within a Secure Session.
     *
     * @param cardChallenge A byte array containing the card challenge.
     * @param pin A byte array containing the 4-byte PIN value.
     * @param kif The PIN encryption key KIF.
     * @param kvc The PIN encryption key KVC.
     * @return A byte array containing the encrypted data block to sent to the card.
     * @throw SymmetricCryptoException If an internal error occurred.
     * @throw SymmetricCryptoIOException If an IO error occurred when processing a command.
     * @since 0.1.0
     */
    virtual const std::vector<uint8_t>& cipherPinForPresentation(
        const std::vector<uint8_t>& cardChallenge,
        const std::vector<uint8_t>& pin,
        const std::shared_ptr<uint8_t> kif,
        const std::shared_ptr<uint8_t> kvc)
        = 0;

    /**
     * Computes a block of encrypted data to be sent to the card for a PIN modification.
     *
     * <p>Note: the {@code kif} and {@code kvc} parameters are ignored when PIN modification is
     * performed within a Secure Session.
     *
     * @param cardChallenge A byte array containing the card challenge.
     * @param currentPin A byte array containing the 4-byte current PIN value.
     * @param newPin A byte array containing the 4-byte new PIN value.
     * @param kif The PIN encryption key KIF.
     * @param kvc The PIN encryption key KVC.
     * @return A byte array containing the encrypted data block to sent to the card.
     * @throw SymmetricCryptoException If an internal error occurred.
     * @throw SymmetricCryptoIOException If an IO error occurred when processing a command.
     * @since 0.1.0
     */
    virtual const std::vector<uint8_t>& cipherPinForModification(
        const std::vector<uint8_t>& cardChallenge,
        const std::vector<uint8_t>& currentPin,
        const std::vector<uint8_t>& newPin,
        const std::shared_ptr<uint8_t> kif,
        const std::shared_ptr<uint8_t> kvc)
        = 0;

    /**
     * Generates an encrypted key data block for loading a key into a card.
     *
     * @param cardChallenge A byte array containing the card challenge.
     * @param issuerKeyKif The issuer key KIF.
     * @param issuerKeyKvc The issuer key KVC.
     * @param targetKeyKif The target key KIF.
     * @param targetKeyKvc The target key KVC.
     * @return A byte array containing the encrypted data block to sent to the card.
     * @throw SymmetricCryptoException If an internal error occurred.
     * @throw SymmetricCryptoIOException If an IO error occurred when processing a command.
     * @since 0.1.0
     */
    virtual const std::vector<uint8_t>& generateCipheredCardKey(
        const std::vector<uint8_t>& cardChallenge,
        const uint8_t issuerKeyKif,
        const uint8_t issuerKeyKvc,
        const uint8_t targetKeyKif,
        const uint8_t targetKeyKvc)
        = 0;

    /**
     * Synchronizes data of the associated card transaction crypto extension if needed.
     *
     * @throws SymmetricCryptoException If an internal error occurred.
     * @throws SymmetricCryptoIOException If an IO error occurred when processing a command.
     * @since 0.1.0
     */
    virtual void synchronize() = 0;
};

} /* namespace spi */
} /* namespace symmetric */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace keypop */
