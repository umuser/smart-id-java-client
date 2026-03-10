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

import java.security.NoSuchAlgorithmException;
import java.security.Signature;

import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;

/**
 * {@link SignatureFactory} implementation for legacy RSASSA-PKCS#1 v1.5 algorithms (signing only).
 */
public final class RsaSsaPkcs1SignatureFactory implements SignatureFactory {

    private final SigningSignatureAlgorithm signingSignatureAlgorithm;

    /**
     * Creates a factory for legacy RSA (RSASSA-PKCS#1 v1.5) signature verification.
     *
     * @param signingSignatureAlgorithm the signature algorithm; must not be null and must be a legacy RSA algorithm
     * @throws SmartIdClientException                if {@code signingSignatureAlgorithm} is null
     * @throws UnprocessableSmartIdResponseException if the algorithm is not a legacy RSA algorithm
     */
    public RsaSsaPkcs1SignatureFactory(SigningSignatureAlgorithm signingSignatureAlgorithm) {
        if (signingSignatureAlgorithm == null) {
            throw new SmartIdClientException("Parameter 'signatureAlgorithmName' is not provided");
        }
        if (!signingSignatureAlgorithm.isLegacyRsa()) {
            throw new UnprocessableSmartIdResponseException("Signature algorithm '" + signingSignatureAlgorithm +
                    "' is not a legacy RSA (RSASSA-PKCS#1 v1.5) algorithm; use validate(..., RsaSsaPssParameters) for RSASSA-PSS");
        }
        this.signingSignatureAlgorithm = signingSignatureAlgorithm;
    }

    @Override
    public Signature getSignature() {
        try {
            return Signature.getInstance(signingSignatureAlgorithm.getJceAlgorithmName());
        } catch (NoSuchAlgorithmException ex) {
            throw new UnprocessableSmartIdResponseException("Signature value validation failed", ex);
        }
    }
}
