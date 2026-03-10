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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;

class Pkcs15SignatureFactoryTest {

    @Test
    void constructor_nullAlgorithm_throwException() {
        var ex = assertThrows(SmartIdClientException.class, () -> new Pkcs15SignatureFactory(null));
        assertEquals("Parameter 'signatureAlgorithmName' is not provided", ex.getMessage());
    }

    @Test
    void constructor_nonLegacyAlgorithm_throwException() {
        var ex = assertThrows(UnprocessableSmartIdResponseException.class,
                () -> new Pkcs15SignatureFactory(SigningSignatureAlgorithm.RSASSA_PSS));
        assertTrue(ex.getMessage().contains("not a legacy RSA"));
    }

    @Test
    void getSignature_legacyAlgorithm_returnsSignatureInstance() {
        var factory = new Pkcs15SignatureFactory(SigningSignatureAlgorithm.SHA256_WITH_RSA_ENCRYPTION);

        var signature = factory.getSignature();

        assertNotNull(signature);
        assertEquals(SigningSignatureAlgorithm.SHA256_WITH_RSA_ENCRYPTION.getJceAlgorithmName(), signature.getAlgorithm());
    }
}
