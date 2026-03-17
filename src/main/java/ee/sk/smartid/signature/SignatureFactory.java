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

import java.security.Signature;

/**
 * Factory for creating preconfigured {@link Signature} instances used when
 * validating Smart-ID signatures.
 * <p>
 * Implementations encapsulate the details of the concrete signature algorithm
 * (for example RSASSA-PSS or legacy RSASSA-PKCS#1 v1.5) so that callers can
 * obtain a correctly initialised {@link Signature} object without dealing with
 * low-level JCA configuration.
 */
public interface SignatureFactory {

    /**
     * Creates a new {@link Signature} instance configured for the underlying
     * Smart-ID signature algorithm.
     *
     * @return a configured {@link Signature} implementation ready for public key
     *         initialization
     */
    Signature getSignature();
}
