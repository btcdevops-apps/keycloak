/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.jose.jws.crypto;

import org.keycloak.common.util.PemUtils;
import org.keycloak.jose.jws.Algorithm;
import org.keycloak.jose.jws.JWSInput;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;

/**
 * @author <a href="mailto:thomas.darimont@gmail.com">Thomas Darimont</a>
 */
class CryptoProviderUtils {

    private CryptoProviderUtils(){}

    static byte[] sign(byte[] data, Algorithm algorithm, PrivateKey privateKey, Signature signature) {
        try {
            signature.initSign(privateKey);
            signature.update(data);
            return signature.sign();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    static boolean verifyViaCertificate(JWSInput input, String cert, Signature signature) {

        X509Certificate certificate;
        try {
            certificate = PemUtils.decodeCertificate(cert);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        return verify(input, certificate.getPublicKey(), signature);
    }

    static boolean verify(JWSInput input, PublicKey publicKey, Signature verifier) {
        try {
            verifier.initVerify(publicKey);
            verifier.update(input.getEncodedSignatureInput().getBytes("UTF-8"));
            return verifier.verify(input.getSignature());
        } catch (Exception e) {
            return false;
        }
    }
}
