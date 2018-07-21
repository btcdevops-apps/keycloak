/*
 * Copyright 2018 Red Hat, Inc. and/or its affiliates
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
package org.keycloak.policy;

import org.jboss.logging.Logger;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * A {@link PasswordPolicyProvider} for <a href="https://haveibeenpwned.com/">Have I Been Pwned</a>'s online
 * database for password breaches. Uses a k-anonymous API which transmits only 20 bits of a password hash.
 * At the time of this writing, there is no rate limit on the Pwned Passwords API.
 *
 * @author <a href="mailto:thomas.darimont@gmail.com">Thomas Darimont</a>
 * @see <a href="https://haveibeenpwned.com/API/v2#SearchingPwnedPasswordsByRange">Searching by range in order to protect the value of the source</a>
 */
public class HaveIBeenPwnedPasswordPolicyProvider implements PasswordPolicyProvider {

    private static final Logger LOG = Logger.getLogger(HaveIBeenPwnedPasswordPolicyProvider.class);

    public static final String ERROR_MESSAGE = "invalidPasswordPwnedPasswordMessage";
    public static final String PWNEDPASSWORDS_API_RANGE_QUERY_URL = "https://api.pwnedpasswords.com/range/";

    private final KeycloakSession session;

    public HaveIBeenPwnedPasswordPolicyProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public PolicyError validate(RealmModel realm, UserModel user, String password) {
        return validate(user.getUsername(), password);
    }


    @Override
    public PolicyError validate(String user, String password) {
        PasswordPolicy policy = session.getContext().getRealm().getPasswordPolicy();
        int threshold = policy.getPolicyConfig(HaveIBeenPwnedPasswordPolicyProviderFactory.ID);
        try {
            MessageDigest sha1 = MessageDigest.getInstance("SHA1");
            String hash = toHexString((sha1.digest(password.getBytes(StandardCharsets.UTF_8))));
            String prefix = hash.substring(0, 5);
            String suffix = hash.substring(5);
            String url = PWNEDPASSWORDS_API_RANGE_QUERY_URL + prefix;

            LOG.debug("starting check for known password breach with api.pwnedpasswords.com");
            SimpleHttp.Response response = SimpleHttp
                    .doGet(url, session)
                    .header("User-Agent", "keycloak")
                    .asResponse();
            LOG.debug("Finished check for known password breach with api.pwnedpasswords.com");

            if (response.getStatus() != 200) {
                LOG.error("Problem during check for known password breach with api.pwnedpasswords.com. " +
                        "Unexpected response from server: " + response.getStatus());
                return null;
            }
            boolean pwned = isPasswordKnownToBePwned(threshold, suffix, response.asString());
            if (pwned) {
                return new PolicyError(ERROR_MESSAGE);
            }
            return null;
        } catch (Exception e) {
            LOG.error("Problem during check for known password breach with api.pwnedpasswords.com.", e);
            return null;
        }
    }


    /**
     * Checks if the given password hex suffix is contained within the {@code Have I Been Pwned} password breach database.
     * <p>
     * Format is:
     * <pre>
     * $suffix:$breachCount
     * 016CA56297B9B88996873773004056A7B84:1
     * 017ABC2B8FC618980E355790169BBB66F5E:1
     * ...
     * </pre>
     *
     * @param threshold    of acceptable number password occurrences in known breaches
     * @param suffix       of the original password as hex string
     * @param responseBody of the password API response
     * @return {@literal true} if the password was contained in a breached database and the occurence count exceeds the given threshold, otherwise {@literal false}.
     */
    private boolean isPasswordKnownToBePwned(int threshold, String suffix, String responseBody) {
        String[] lines = responseBody.split("\r\n");
        return Arrays.stream(lines)
                .filter(s -> s.startsWith(suffix))
                .mapToInt(s -> Integer.parseInt(s.split(":", 2)[1]))
                .anyMatch(t -> t >= threshold);
    }

    @Override
    public Object parseConfig(String value) {
        return parseInteger(value, HaveIBeenPwnedPasswordPolicyProviderFactory.DEFAULT_VALUE);
    }

    @Override
    public void close() {
        //NOOP
    }

    private static String toHexString(byte[] bytes) {
        StringBuilder s = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            s.append(String.format("%02X", bytes[i]));
        }
        return s.toString();
    }
}
