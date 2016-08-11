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

package org.keycloak.authentication.authenticators.browser;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.common.util.Base64;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.OTPPolicy;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.services.messages.Messages;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedList;
import java.util.List;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class OTPFormAuthenticator extends AbstractUsernameFormAuthenticator implements Authenticator {
    public static final String TOTP_FORM_ACTION = "totp";

    private static final String OTP_HASHES_ATTRIBUTE = "_otpHashes";

    @Override
    public void action(AuthenticationFlowContext context) {
        validateOTP(context);
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        Response challengeResponse = challenge(context, null);
        context.challenge(challengeResponse);
    }

    public void validateOTP(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> inputData = context.getHttpRequest().getDecodedFormParameters();
        if (inputData.containsKey("cancel")) {
            context.resetFlow();
            return;
        }
        List<UserCredentialModel> credentials = new LinkedList<>();
        String password = inputData.getFirst(CredentialRepresentation.TOTP);
        if (password == null) {
            Response challengeResponse = challenge(context, null);
            context.challenge(challengeResponse);
            return;
        }
        OTPPolicy otpPolicy = context.getRealm().getOTPPolicy();
        credentials.add(UserCredentialModel.otp(otpPolicy.getType(), password));

        String currentOtpHash = hashOtpCode(password);

        if (otpCodeWasAlreadyUsed(context, currentOtpHash)) {
            context.getEvent().user(context.getUser())
                    .error(Errors.INVALID_USER_CREDENTIALS);
            Response challengeResponse = challenge(context, Messages.INVALID_TOTP_CODE_ALREADY_USED);
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challengeResponse);
            return;
        }

        boolean valid = context.getSession().users().validCredentials(context.getSession(), context.getRealm(), context.getUser(), credentials);

        if (!valid) {
            context.getEvent().user(context.getUser())
                    .error(Errors.INVALID_USER_CREDENTIALS);
            Response challengeResponse = challenge(context, Messages.INVALID_TOTP);
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challengeResponse);
            return;
        }

        updateOtpHashes(context.getUser(), currentOtpHash, otpPolicy);

        context.success();
    }

    /**
     * Remember the last n hashed otp tokens, where n is the width of the {@link OTPPolicy#lookAheadWindow}.
     *
     * @param user
     * @param currentOtpHash
     * @param otpPolicy
     */
    private void updateOtpHashes(UserModel user, String currentOtpHash, OTPPolicy otpPolicy) {

        //TODO store OTP_HASHES in dedicated cache
        String otpHashes = user.getFirstAttribute(OTP_HASHES_ATTRIBUTE);

        String[] hashes;
        if (otpHashes == null) {
            //first otp usage
            hashes = new String[otpPolicy.getLookAheadWindow()];
        } else {
            String[] presentHashes = otpHashes.split(";");
            if (presentHashes.length == otpPolicy.getLookAheadWindow()) {
                // lookAheadPolicy still the same take the values as is
                hashes = presentHashes;
            } else {

                // lookAheadPolicy was changed - copy over the most recent values
                hashes = new String[otpPolicy.getLookAheadWindow()];
                for (int i = 0, len = Math.min(hashes.length, presentHashes.length); i < len; i++) {
                    hashes[hashes.length-1-i] = presentHashes[presentHashes.length-1-i];
                }
            }
        }

        // move the stored hashes 1 to the right
        System.arraycopy(hashes, 1, hashes, 0, hashes.length - 1);

        // store the new otp hash in the last slot
        hashes[hashes.length - 1] = currentOtpHash;

        //TODO store OTP_HASHES in dedicated cache
        user.setSingleAttribute(OTP_HASHES_ATTRIBUTE, String.join(";", hashes));
    }

    private boolean otpCodeWasAlreadyUsed(AuthenticationFlowContext context, String currentOtpHash) {

        String otpHashes = context.getUser().getFirstAttribute(OTP_HASHES_ATTRIBUTE);
        return otpHashes != null && otpHashes.contains(currentOtpHash);
    }

    private String hashOtpCode(String code) {

        try {
            MessageDigest sha1 = MessageDigest.getInstance("SHA1");
            byte[] digest = sha1.digest(code.getBytes(StandardCharsets.UTF_8));
            String hashed = Base64.encodeBytes(digest);
            return hashed;
        } catch (NoSuchAlgorithmException cannotHappen) {
            throw new RuntimeException("SHA1 Algorithm not found");
        }
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    protected Response challenge(AuthenticationFlowContext context, String error) {
        LoginFormsProvider forms = context.form();
        if (error != null) forms.setError(error);

        return forms.createLoginTotp();
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return session.users().configuredForCredentialType(realm.getOTPPolicy().getType(), realm, user);
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        if (!user.getRequiredActions().contains(UserModel.RequiredAction.CONFIGURE_TOTP.name())) {
            user.addRequiredAction(UserModel.RequiredAction.CONFIGURE_TOTP.name());
        }

    }


    @Override
    public void close() {

    }
}
