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

import java.util.Arrays;

/**
 * Signature algorithms supported for signing sessions.
 * <p>
 * Includes RSASSA-PSS and RSASSA-PKCS#1 v1.5 algorithms. The latter are marked as legacy RSA.
 */
public enum SigningSignatureAlgorithm {

    /**
     * RSASSA-PSS (RSA Probabilistic Signature Scheme) as defined in PKCS #1 v2.1.
     */
    RSASSA_PSS("rsassa-pss", false, "rsassa-pss", null),

    /**
     * RSASSA-PKCS#1 v1.5 with SHA-256. Signing only; no signatureAlgorithmParameters.
     */
    SHA256_WITH_RSA_ENCRYPTION("sha256WithRSAEncryption", true, "SHA256withRSA", HashAlgorithm.SHA_256),

    /**
     * RSASSA-PKCS#1 v1.5 with SHA-384. Signing only; no signatureAlgorithmParameters.
     */
    SHA384_WITH_RSA_ENCRYPTION("sha384WithRSAEncryption", true, "SHA384withRSA", HashAlgorithm.SHA_384),

    /**
     * RSASSA-PKCS#1 v1.5 with SHA-512. Signing only; no signatureAlgorithmParameters.
     */
    SHA512_WITH_RSA_ENCRYPTION("sha512WithRSAEncryption", true, "SHA512withRSA", HashAlgorithm.SHA_512);

    private final String algorithmName;
    private final boolean legacyRsa;
    private final String jceAlgorithmName;
    private final HashAlgorithm hashAlgorithmForLegacy;

    SigningSignatureAlgorithm(String algorithmName,
                              boolean legacyRsa,
                              String jceAlgorithmName,
                              HashAlgorithm hashAlgorithmForLegacy) {
        this.algorithmName = algorithmName;
        this.legacyRsa = legacyRsa;
        this.jceAlgorithmName = jceAlgorithmName;
        this.hashAlgorithmForLegacy = hashAlgorithmForLegacy;
    }

    /**
     * Provides the signature algorithm name as used in the Smart-ID API.
     *
     * @return the signature algorithm name
     */
    public String getAlgorithmName() {
        return algorithmName;
    }

    /**
     * Returns whether this algorithm is RSASSA-PKCS#1 v1.5 (legacy RSA).
     * Such algorithms do not use or require {@code signatureAlgorithmParameters} in requests or responses.
     *
     * @return true for SHA256/SHA384/SHA512 with RSA encryption
     */
    public boolean isLegacyRsa() {
        return legacyRsa;
    }

    /**
     * Returns the JCE standard algorithm name for {@link java.security.Signature#getInstance(String)}.
     * For legacy RSA algorithms this is the name used to verify the signature (e.g. SHA256withRSA).
     *
     * @return the JCE algorithm name
     */
    public String getJceAlgorithmName() {
        return jceAlgorithmName;
    }

    /**
     * Returns the hash algorithm for legacy RSA algorithms. Used when creating {@link SignableData}
     * so that {@link SignableData#calculateHash()} uses the correct hash for the signature algorithm.
     *
     * @return the hash algorithm for legacy algorithms, or null for RSASSA_PSS
     */
    public HashAlgorithm getHashAlgorithmForLegacy() {
        return hashAlgorithmForLegacy;
    }

    /**
     * Checks if the provided signature algorithm is supported for signing.
     *
     * @param signatureAlgorithm the signature algorithm name to check
     * @return true if the signature algorithm is supported, false otherwise
     */
    public static boolean isSupported(String signatureAlgorithm) {
        return Arrays.stream(SigningSignatureAlgorithm.values())
                .anyMatch(s -> s.getAlgorithmName().equals(signatureAlgorithm));
    }

    /**
     * Returns whether the given algorithm name is a legacy RSA (RSASSA-PKCS#1 v1.5) algorithm.
     *
     * @param signatureAlgorithm the signature algorithm name
     * @return true if legacy RSA, false otherwise
     */
    public static boolean isLegacyRsa(String signatureAlgorithm) {
        return Arrays.stream(SigningSignatureAlgorithm.values())
                .filter(s -> s.getAlgorithmName().equals(signatureAlgorithm))
                .anyMatch(SigningSignatureAlgorithm::isLegacyRsa);
    }

    /**
     * Converts a string representation of a signature algorithm to its corresponding enum value.
     *
     * @param signatureAlgorithm the signature algorithm name
     * @return the corresponding SigningSignatureAlgorithm enum value
     * @throws IllegalArgumentException if the provided signature algorithm is not supported
     */
    public static SigningSignatureAlgorithm fromString(String signatureAlgorithm) {
        return Arrays
                .stream(SigningSignatureAlgorithm.values())
                .filter(s -> s.getAlgorithmName().equals(signatureAlgorithm))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Invalid signatureAlgorithm value: " + signatureAlgorithm));
    }
}

