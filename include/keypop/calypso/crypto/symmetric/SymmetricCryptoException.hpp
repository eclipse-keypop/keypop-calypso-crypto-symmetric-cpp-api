/******************************************************************************
 * Copyright (c) 2025 Calypso Networks Association https://calypsonet.org/    *
 *                                                                            *
 * This program and the accompanying materials are made available under the   *
 * terms of the MIT License which is available at                             *
 * https://opensource.org/licenses/MIT.                                       *
 *                                                                            *
 * SPDX-License-Identifier: MIT                                               *
 ******************************************************************************/

#pragma once

#include <memory>
#include <stdexcept>
#include <string>

namespace keypop {
namespace calypso {
namespace crypto {
namespace symmetric {

/**
 * Indicates that an error occurred when processing a command.
 *
 * @since 0.1.0
 */
class SymmetricCryptoException final : public std::exception {
public:
    /**
     * @param message The message to identify the exception context.
     * @since 0.1.0
     */
    explicit SymmetricCryptoException(const std::string& /*message*/)
    : std::exception()
    {
    }

    /**
     * Encapsulates a lower level exception.
     *
     * @param message Message to identify the exception context.
     * @param cause The cause.
     * @since 0.1.0
     */
    SymmetricCryptoException(
        const std::string& /*message*/, const std::exception& cause)
    : std::exception(cause)
    {
    }
};

} /* namespace symmetric */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace keypop */
