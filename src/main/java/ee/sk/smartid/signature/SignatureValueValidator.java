package ee.sk.smartid.signature;

/*-
 * #%L
 * Smart ID sample Java client
 * %%
 * Copyright (C) 2018 - 2026 SK ID Solutions AS
 * %%
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 * #L%
 */

import java.security.cert.X509Certificate;

import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;

/**
 * Interface for signature value validator.
 * <p>
 * Use a concrete {@link SignatureFactory} implementation to specify the signature algorithm and parameters:
 * {@link RsaSsaPssSignatureFactory} for RSASSA-PSS (authentication and signing), or
 * {@link RsaSsaPkcs1SignatureFactory} for legacy RSASSA-PKCS#1 v1.5 algorithms (signing only).
 * The factory encapsulates algorithm choice and parameter validation.
 */
public interface SignatureValueValidator {

    /**
     * Validates the signature value using the provided signature factory.
     *
     * @param signatureValue   the signature value to validate
     * @param payload          the original data that was signed (typically the hash that was sent to Smart-ID)
     * @param certificate      X.509 certificate used for signature validation
     * @param signatureFactory factory that creates the {@link java.security.Signature} instance for verification
     * @throws UnprocessableSmartIdResponseException when there is any issue with validating the signature value
     */
    void validate(byte[] signatureValue,
                  byte[] payload,
                  X509Certificate certificate,
                  SignatureFactory signatureFactory);
}
