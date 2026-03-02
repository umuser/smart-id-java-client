package ee.sk.smartid;

/*-
 * #%L
 * Smart ID sample Java client
 * %%
 * Copyright (C) 2018 - 2025 SK ID Solutions AS
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
 * Signature algorithms supported by Smart-ID API.
 * <p>
 * Algorithms are divided by use case:
 * <ul>
 *   <li><b>Authentication</b>: only {@link #RSASSA_PSS} is supported for authentication sessions.</li>
 *   <li><b>Signing</b>: {@link #RSASSA_PSS} and the RSASSA-PKCS#1 v1.5 algorithms
 *   ({@link #SHA256_WITH_RSA_ENCRYPTION}, {@link #SHA384_WITH_RSA_ENCRYPTION}, {@link #SHA512_WITH_RSA_ENCRYPTION})
 *   are supported for signature sessions.</li>
 * </ul>
 * RSASSA-PKCS#1 v1.5 algorithms do not use {@code signatureAlgorithmParameters} in the API request or response.
 */
public enum SignatureAlgorithm {

    /**
     * RSASSA-PSS (RSA Probabilistic Signature Scheme) as defined in PKCS #1 v2.1.
     * Supported for both authentication and signing.
     */
    RSASSA_PSS("rsassa-pss", false, true),

    /**
     * RSASSA-PKCS#1 v1.5 with SHA-256. Signing only; no signatureAlgorithmParameters.
     */
    SHA256_WITH_RSA_ENCRYPTION("sha256WithRSAEncryption", true, false, "SHA256withRSA"),

    /**
     * RSASSA-PKCS#1 v1.5 with SHA-384. Signing only; no signatureAlgorithmParameters.
     */
    SHA384_WITH_RSA_ENCRYPTION("sha384WithRSAEncryption", true, false, "SHA384withRSA"),

    /**
     * RSASSA-PKCS#1 v1.5 with SHA-512. Signing only; no signatureAlgorithmParameters.
     */
    SHA512_WITH_RSA_ENCRYPTION("sha512WithRSAEncryption", true, false, "SHA512withRSA");

    private final String algorithmName;
    private final boolean legacyRsa;
    private final boolean usedForAuthentication;
    private final String jceAlgorithmName;

    SignatureAlgorithm(String algorithmName, boolean legacyRsa, boolean usedForAuthentication) {
        this(algorithmName, legacyRsa, usedForAuthentication, algorithmName);
    }

    SignatureAlgorithm(String algorithmName, boolean legacyRsa, boolean usedForAuthentication, String jceAlgorithmName) {
        this.algorithmName = algorithmName;
        this.legacyRsa = legacyRsa;
        this.usedForAuthentication = usedForAuthentication;
        this.jceAlgorithmName = jceAlgorithmName;
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
     * Returns whether this algorithm is supported for authentication sessions.
     * Only RSASSA-PSS is supported for authentication.
     *
     * @return true if the algorithm may be used for authentication
     */
    public boolean isUsedForAuthentication() {
        return usedForAuthentication;
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
     * Checks if the provided signature algorithm is supported.
     *
     * @param signatureAlgorithm the signature algorithm name to check
     * @return true if the signature algorithm is supported, false otherwise
     */
    public static boolean isSupported(String signatureAlgorithm) {
        return Arrays.stream(SignatureAlgorithm.values())
                .anyMatch(s -> s.getAlgorithmName().equals(signatureAlgorithm));
    }

    /**
     * Returns whether the given algorithm name is a legacy RSA (RSASSA-PKCS#1 v1.5) algorithm.
     *
     * @param signatureAlgorithm the signature algorithm name
     * @return true if legacy RSA, false otherwise
     */
    public static boolean isLegacyRsa(String signatureAlgorithm) {
        return Arrays.stream(SignatureAlgorithm.values())
                .filter(s -> s.getAlgorithmName().equals(signatureAlgorithm))
                .anyMatch(SignatureAlgorithm::isLegacyRsa);
    }

    /**
     * Converts a string representation of a signature algorithm to its corresponding enum value.
     *
     * @param signatureAlgorithm the signature algorithm name
     * @return the corresponding SignatureAlgorithm enum value
     * @throws IllegalArgumentException if the provided signature algorithm is not supported
     */
    public static SignatureAlgorithm fromString(String signatureAlgorithm) {
        return Arrays
                .stream(SignatureAlgorithm.values())
                .filter(s -> s.getAlgorithmName().equals(signatureAlgorithm))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Invalid signatureAlgorithm value: " + signatureAlgorithm));
    }
}
