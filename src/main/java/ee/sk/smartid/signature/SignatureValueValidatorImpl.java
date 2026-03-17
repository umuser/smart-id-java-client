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

import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.cert.X509Certificate;

import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;

/**
 * Implementation of {@link SignatureValueValidator} that validates signature values
 * for both RSASSA-PSS (authentication and signing) and RSASSA-PKCS#1 v1.5 (signing only).
 */
public final class SignatureValueValidatorImpl implements SignatureValueValidator {

    @Override
    public void validate(byte[] signatureValue,
                         byte[] payload,
                         X509Certificate certificate,
                         SignatureFactory signatureFactory) {
        if (signatureValue == null) {
            throw new SmartIdClientException("Parameter 'signatureValue' is not provided");
        }
        if (payload == null) {
            throw new SmartIdClientException("Parameter 'payload' is not provided");
        }
        if (certificate == null) {
            throw new SmartIdClientException("Parameter 'certificate' is not provided");
        }
        if (signatureFactory == null) {
            throw new SmartIdClientException("Parameter 'signatureFactory' is not provided");
        }
        try {
            Signature signature = signatureFactory.getSignature();
            signature.initVerify(certificate.getPublicKey());
            signature.update(payload);
            if (!signature.verify(signatureValue)) {
                throw new UnprocessableSmartIdResponseException("Provided signature value does not match the calculated signature value");
            }
        } catch (GeneralSecurityException ex) {
            throw new UnprocessableSmartIdResponseException("Signature value validation failed", ex);
        }
    }
}
