/**************************************************************************************************
 * Copyright (c) 2024 Calypso Networks Association https://calypsonet.org/                        *
 *                                                                                                *
 * This program and the accompanying materials are made available under the                       *
 * terms of the MIT License which is available at https://opensource.org/licenses/MIT.            *
 *                                                                                                *
 * SPDX-License-Identifier: MIT                                                                   *
 **************************************************************************************************/

#pragma once

#include <cstdint>
#include <vector>

namespace keypop {
namespace calypso {
namespace crypto {
namespace symmetric {

/**
 * Contains the input/output data of the SV command operations (LOAD / DEBIT / UNDEBIT).
 *
 * @since 0.1.0
 */
class SvCommandSecurityDataApi {
public:
    /**
     * Returns the "SV Get" ingoing command data.
     *
     * @return A not empty byte array containing the "SV Get" apdu request data.
     * @since 0.1.0
     */
    virtual const std::vector<uint8_t>& getSvGetRequest() const = 0;

    /**
     * Returns the "SV Get" outgoing command data.
     *
     * @return A not empty byte array containing the "SV Get" apdu response data.
     * @since 0.1.0
     */
    virtual const std::vector<uint8_t>& getSvGetResponse() const = 0;

    /**
     * Returns the "SV Load/Debit/Undebit" ingoing partial command data.
     *
     * @return A not empty byte array containing the "SV Load/Debit/Undebit" apdu request data.
     * @since 0.1.0
     */
    virtual const std::vector<uint8_t>& getSvCommandPartialRequest() const = 0;

    /**
     * Sets the serial number to be placed in the "SV Load/Debit/Undebit" command request.
     *
     * @param serialNumber The serial number to be used.
     * @return The current instance.
     * @since 0.1.0
     */
    virtual SvCommandSecurityDataApi& setSerialNumber(const std::vector<uint8_t>& serialNumber) = 0;

    /**
     * Sets the transaction number to be placed in the "SV Load/Debit/Undebit" command request.
     *
     * @param transactionNumber The transaction number to be used.
     * @return The current instance.
     * @since 0.1.0
     */
    virtual SvCommandSecurityDataApi&
    setTransactionNumber(const std::vector<uint8_t>& transactionNumber)
        = 0;

    /**
     * Sets the terminal challenge to be placed in the SV Load/Debit/Undebit command request.
     *
     * @param terminalChallenge The terminal challenge to be used.
     * @return The current instance.
     * @since 0.1.0
     */
    virtual SvCommandSecurityDataApi
    setTerminalChallenge(const std::vector<uint8_t>& terminalChallenge)
        = 0;

    /**
     * Sets the terminal SV MAC to be placed in the "SV Load/Debit/Undebit" command request.
     *
     * @param terminalSvMac The terminal SV MAC to be used.
     * @return The current instance.
     * @since 0.1.0
     */
    virtual SvCommandSecurityDataApi setTerminalSvMac(const std::vector<uint8_t>& terminalSvMac)
        = 0;
};

} /* namespace symmetric */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace keypop */
