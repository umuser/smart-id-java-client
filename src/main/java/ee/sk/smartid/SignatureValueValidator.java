package ee.sk.smartid;

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
 */
public interface SignatureValueValidator {

    /**
     * Validates the signature value for RSASSA-PSS (authentication and signing).
     *
     * @param signatureValue       the signature value to validate
     * @param payload              the original data that was signed (typically the hash that was sent to Smart-ID)
     * @param certificate          X.509 certificate used for signature validation
     * @param rsaSsaPssParameters  signature parameters used for creating the signature value
     * @throws UnprocessableSmartIdResponseException when there is any issue with validating the signature value
     */
    void validateRsaSsaPss(byte[] signatureValue,
                           byte[] payload,
                           X509Certificate certificate,
                           RsaSsaPssParameters rsaSsaPssParameters);

    /**
     * Validates the signature value for legacy RSASSA-PKCS#1 v1.5 algorithms (signing only).
     * Use this when the signature session used a legacy RSA algorithm (e.g. {@code sha256WithRSAEncryption}).
     *
     * @param signatureValue        the signature value to validate
     * @param payload               the digest or data that was signed (typically the hash that was sent to Smart-ID)
     * @param certificate           X.509 certificate used for signature validation
     * @param signatureAlgorithmName Smart-ID API algorithm name (e.g. {@code sha512WithRSAEncryption})
     * @throws UnprocessableSmartIdResponseException when there is any issue with validating the signature value
     */
    void validateLegacyRsa(byte[] signatureValue,
                           byte[] payload,
                           X509Certificate certificate,
                           String signatureAlgorithmName);

    /**
     * Validates the signature value for both RSASSA-PSS and legacy RSASSA-PKCS#1 v1.5 algorithms.
     * <ul>
     *     <li>For RSASSA-PSS ({@link SigningSignatureAlgorithm#RSASSA_PSS}) the {@code rsaSsaPssParameters}
     *     parameter <b>must</b> be provided.</li>
     *     <li>For legacy RSA algorithms (e.g. {@code sha256WithRSAEncryption}) the {@code rsaSsaPssParameters}
     *     parameter <b>must be {@code null}</b>.</li>
     * </ul>
     *
     * @param signatureValue        the signature value to validate
     * @param payload               the data used when calculating the signature (hash or raw bytes, depending on the algorithm)
     * @param certificate           X.509 certificate used for signature validation
     * @param signatureAlgorithmName Smart-ID API algorithm name
     * @param rsaSsaPssParameters   RSASSA-PSS parameters; required only for RSASSA-PSS and must be {@code null} for legacy RSA
     * @throws UnprocessableSmartIdResponseException when there is any issue with validating the signature value
     */
    void validate(byte[] signatureValue,
                  byte[] payload,
                  X509Certificate certificate,
                  String signatureAlgorithmName,
                  RsaSsaPssParameters rsaSsaPssParameters);
}
