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
#include <stdexcept>
#include <string>

namespace keypop {
namespace calypso {
namespace crypto {
namespace symmetric {

/**
 * Indicates that an IO error occurred when processing a command.
 *
 * @since 0.1.0
 */
class SymmetricCryptoIOException final : std::exception {
public:
    /**
     * @param message The message to identify the exception context.
     * @since 0.1.0
     */
    explicit SymmetricCryptoIOException(const std::string& message)
    : std::exception() {
        (void)message;
    }

    /**
     * Encapsulates a lower level exception.
     *
     * @param message Message to identify the exception context.
     * @param cause The cause.
     * @since 0.1.0
     */
    SymmetricCryptoIOException(
        const std::string& message, const std::shared_ptr<std::exception> cause)
    : std::exception(*cause) {
        (void)message;
    }
};

} /* namespace symmetric */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace keypop */
