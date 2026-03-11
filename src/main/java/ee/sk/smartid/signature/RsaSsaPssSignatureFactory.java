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

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;

/**
 * {@link SignatureFactory} implementation for RSASSA-PSS (authentication and signing).
 */
public final class RsaSsaPssSignatureFactory implements SignatureFactory {

    private static final Logger logger = LoggerFactory.getLogger(RsaSsaPssSignatureFactory.class);

    private final RsaSsaPssParameters rsaSsaPssParameters;

    /**
     * Creates a factory for RSASSA-PSS signature verification.
     *
     * @param rsaSsaPssParameters signature parameters; must not be null
     * @throws SmartIdClientException if {@code rsaSsaPssParameters} is null
     */
    public RsaSsaPssSignatureFactory(RsaSsaPssParameters rsaSsaPssParameters) {
        if (rsaSsaPssParameters == null) {
            throw new SmartIdClientException("Parameter 'rsaSsaPssParameters' is not provided");
        }
        this.rsaSsaPssParameters = rsaSsaPssParameters;
    }

    @Override
    public Signature getSignature() {
        try {
            var params = new PSSParameterSpec(rsaSsaPssParameters.getDigestHashAlgorithm().getAlgorithmName(),
                    rsaSsaPssParameters.getMaskGenAlgorithm().getMgfName(),
                    new MGF1ParameterSpec(rsaSsaPssParameters.getMaskHashAlgorithm().getAlgorithmName()),
                    rsaSsaPssParameters.getSaltLength(),
                    rsaSsaPssParameters.getTrailerField().getPssSpecValue());
            var signature = Signature.getInstance(rsaSsaPssParameters.getSignatureAlgorithmName());
            signature.setParameter(params);
            return signature;
        } catch (NoSuchAlgorithmException ex) {
            logger.error("Invalid signature algorithm name was provided: {}", rsaSsaPssParameters.getSignatureAlgorithmName());
            throw new UnprocessableSmartIdResponseException("Invalid signature algorithm was provided", ex);
        } catch (InvalidAlgorithmParameterException ex) {
            throw new UnprocessableSmartIdResponseException("Invalid signature algorithm parameters were provided", ex);
        }
    }
}
