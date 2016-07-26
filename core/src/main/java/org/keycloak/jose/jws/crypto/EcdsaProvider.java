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

import org.keycloak.jose.jws.Algorithm;
import org.keycloak.jose.jws.JWSInput;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

/**
 * @author <a href="mailto:thomas.darimont@gmail.com">Thomas Darimont</a>
 */
public class EcdsaProvider implements SignatureProvider {

    static String getJavaAlgorithm(Algorithm alg) {
        switch (alg) {
            case ES256:
                return "SHA256withECDSA";
            case ES384:
                return "SHA384withECDSA";
            case ES512:
                return "SHA512withECDSA";
            default:
                throw new IllegalArgumentException("Not an ECDSA Algorithm: " + alg);
        }
    }

    static Signature getSignature(Algorithm alg) {
        try {
            return Signature.getInstance(getJavaAlgorithm(alg));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] sign(byte[] data, Algorithm algorithm, PrivateKey privateKey) {
        return CryptoProviderUtils.sign(data,algorithm,privateKey, getSignature(algorithm));
    }

    public static boolean verify(JWSInput input, PublicKey publicKey) {
        return CryptoProviderUtils.verify(input,publicKey, getSignature(input.getHeader().getAlgorithm()));
    }

    @Override
    public boolean verify(JWSInput input, String key) {
        return CryptoProviderUtils.verifyViaCertificate(input, key, getSignature(input.getHeader().getAlgorithm()));
    }
}
