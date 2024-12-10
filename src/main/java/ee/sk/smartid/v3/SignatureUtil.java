package ee.sk.smartid.v3;

/*-
 * #%L
 * Smart ID sample Java client
 * %%
 * Copyright (C) 2018 - 2024 SK ID Solutions AS
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

import ee.sk.smartid.HashType;
import ee.sk.smartid.exception.permanent.SmartIdClientException;

public class SignatureUtil {

    public static String getDigestToSignBase64(SignableHash signableHash, SignableData signableData) {
        if (signableHash != null && signableHash.areFieldsFilled()) {
            return signableHash.getHashInBase64();
        } else if (signableData != null) {
            if (signableData.getHashType() == null) {
                throw new SmartIdClientException("HashType must be set for signableData.");
            }
            return signableData.calculateHashInBase64();
        } else {
            throw new SmartIdClientException("Either signableHash or signableData must be set.");
        }
    }

    public static String getSignatureAlgorithm(SignatureAlgorithm signatureAlgorithm, SignableHash signableHash, SignableData signableData) {
        if (signatureAlgorithm != null) {
            return signatureAlgorithm.getAlgorithmName();
        } else if (signableHash != null && signableHash.getHashType() != null) {
            return getAlgorithmFromHashType(signableHash.getHashType());
        } else if (signableData != null && signableData.getHashType() != null) {
            return getAlgorithmFromHashType(signableData.getHashType());
        } else {
            return SignatureAlgorithm.SHA512WITHRSA.getAlgorithmName();
        }
    }

    private static String getAlgorithmFromHashType(HashType hashType) {
        return switch (hashType) {
            case SHA256 -> SignatureAlgorithm.SHA256WITHRSA.getAlgorithmName();
            case SHA384 -> SignatureAlgorithm.SHA384WITHRSA.getAlgorithmName();
            case SHA512 -> SignatureAlgorithm.SHA512WITHRSA.getAlgorithmName();
        };
    }
}