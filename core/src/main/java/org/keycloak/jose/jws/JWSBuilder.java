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

package org.keycloak.jose.jws;

import org.keycloak.jose.jws.crypto.EcdsaProvider;
import org.keycloak.jose.jws.crypto.HMACProvider;
import org.keycloak.jose.jws.crypto.RSAProvider;
import org.keycloak.common.util.Base64Url;
import org.keycloak.util.JsonSerialization;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.PrivateKey;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class JWSBuilder {
    String type;
    String kid;
    String contentType;
    byte[] contentBytes;

    public JWSBuilder type(String type) {
        this.type = type;
        return this;
    }

    public JWSBuilder kid(String kid) {
        this.kid = kid;
        return this;
    }

    public JWSBuilder contentType(String type) {
        this.contentType = type;
        return this;
    }

    public EncodingBuilder content(byte[] bytes) {
        this.contentBytes = bytes;
        return new EncodingBuilder();
    }

    public EncodingBuilder jsonContent(Object object) {
        try {
            this.contentBytes = JsonSerialization.writeValueAsBytes(object);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return new EncodingBuilder();
    }


    protected String encodeHeader(Algorithm alg) {
        StringBuilder builder = new StringBuilder("{");
        builder.append("\"alg\":\"").append(alg.toString()).append("\"");

        if (type != null) builder.append(",\"typ\" : \"").append(type).append("\"");
        if (kid != null) builder.append(",\"kid\" : \"").append(kid).append("\"");
        if (contentType != null) builder.append(",\"cty\":\"").append(contentType).append("\"");
        builder.append("}");
        try {
            return Base64Url.encode(builder.toString().getBytes("UTF-8"));
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    protected String encodeAll(StringBuffer encoding, byte[] signature) {
        encoding.append('.');
        if (signature != null) {
            encoding.append(Base64Url.encode(signature));
        }
        return encoding.toString();
    }

    protected void encode(Algorithm alg, byte[] data, StringBuffer encoding) {
        encoding.append(encodeHeader(alg));
        encoding.append('.');
        encoding.append(Base64Url.encode(data));
    }

    protected byte[] marshalContent() {
        return contentBytes;
    }

    public class EncodingBuilder {

        public String sign(Algorithm algorithm, PrivateKey privateKey){

            switch(algorithm){
                case none:
                    return none();
                case HS256:
                    throw new UnsupportedOperationException("HS256");
                case HS384:
                    throw new UnsupportedOperationException("HS384");
                case HS512:
                    throw new UnsupportedOperationException("HS512");
                case RS256:
                    return rsa256(privateKey);
                case RS384:
                    return rsa384(privateKey);
                case RS512:
                    return rsa512(privateKey);
                case ES256:
                    return es256(privateKey);
                case ES384:
                    return es384(privateKey);
                case ES512:
                    return es512(privateKey);

                default:
                    throw new UnsupportedOperationException(algorithm.name());
            }
        }

        public String none() {
            StringBuffer buffer = new StringBuffer();
            byte[] data = marshalContent();
            encode(Algorithm.none, data, buffer);
            return encodeAll(buffer, null);
        }

        public String rsa256(PrivateKey privateKey) {
            return rsaGeneric(privateKey,Algorithm.RS256);
        }

        public String rsa384(PrivateKey privateKey) {
            return rsaGeneric(privateKey,Algorithm.RS384);
        }

        public String rsa512(PrivateKey privateKey) {
            return rsaGeneric(privateKey,Algorithm.RS512);
        }

        private String rsaGeneric(PrivateKey privateKey, Algorithm algo) {
            StringBuffer buffer = new StringBuffer();
            byte[] data = marshalContent();
            encode(algo, data, buffer);
            byte[] signature;
            try {
                signature = RSAProvider.sign(buffer.toString().getBytes("UTF-8"), algo, privateKey);
            } catch (UnsupportedEncodingException e) {
                throw new RuntimeException(e);
            }
            return encodeAll(buffer, signature);
        }

        public String es256(PrivateKey privateKey){
            return esGeneric(privateKey, Algorithm.ES256);
        }

        public String es384(PrivateKey privateKey){
            return esGeneric(privateKey, Algorithm.ES384);
        }

        public String es512(PrivateKey privateKey){
            return esGeneric(privateKey, Algorithm.ES512);
        }

        private String esGeneric(PrivateKey privateKey, Algorithm algorithm){
            StringBuffer buffer = new StringBuffer();
            byte[] data = marshalContent();
            encode(algorithm, data, buffer);
            byte[] signature;
            try {
                signature = EcdsaProvider.sign(buffer.toString().getBytes("UTF-8"), algorithm, privateKey);
            } catch (UnsupportedEncodingException e) {
                throw new RuntimeException(e);
            }
            return encodeAll(buffer, signature);
        }


        public String hmac256(byte[] sharedSecret) {
            return hmacGeneric(sharedSecret,Algorithm.HS256);
        }

        public String hmac384(byte[] sharedSecret) {
            return hmacGeneric(sharedSecret,Algorithm.HS384);
        }

        public String hmac512(byte[] sharedSecret) {
            return hmacGeneric(sharedSecret,Algorithm.HS512);
        }

        private String hmacGeneric(byte[] sharedSecret, Algorithm algo){
            StringBuffer buffer = new StringBuffer();
            byte[] data = marshalContent();
            encode(algo, data, buffer);
            byte[] signature = null;
            try {
                signature = HMACProvider.sign(buffer.toString().getBytes("UTF-8"), algo, sharedSecret);
            } catch (UnsupportedEncodingException e) {
                throw new RuntimeException(e);
            }
            return encodeAll(buffer, signature);
        }

        public String hmac256(SecretKey sharedSecret) {
            return hmacGeneric(sharedSecret, Algorithm.HS256);
        }

        public String hmac384(SecretKey sharedSecret) {
            return hmacGeneric(sharedSecret, Algorithm.HS384);
        }

        public String hmac512(SecretKey sharedSecret) {
            return hmacGeneric(sharedSecret, Algorithm.HS512);
        }

        private String hmacGeneric(SecretKey sharedSecret, Algorithm algo) {
            StringBuffer buffer = new StringBuffer();
            byte[] data = marshalContent();
            encode(algo, data, buffer);
            byte[] signature = null;
            try {
                signature = HMACProvider.sign(buffer.toString().getBytes("UTF-8"), algo, sharedSecret);
            } catch (UnsupportedEncodingException e) {
                throw new RuntimeException(e);
            }
            return encodeAll(buffer, signature);
        }
    }
}
