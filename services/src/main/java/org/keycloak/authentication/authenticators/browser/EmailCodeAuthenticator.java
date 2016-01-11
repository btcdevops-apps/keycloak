package org.keycloak.authentication.authenticators.browser;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailSenderProvider;
import org.keycloak.events.Errors;
import org.keycloak.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.services.messages.Messages;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.util.LinkedList;
import java.util.List;

/**
 * Created by tom on 11.01.16.
 */
public class EmailCodeAuthenticator implements Authenticator {

    @Override
    public void action(AuthenticationFlowContext context) {
        validateCode(context);
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        Response challengeResponse = challenge(context, null);
        context.challenge(challengeResponse);
    }

    public void validateCode(AuthenticationFlowContext context) {

        MultivaluedMap<String, String> inputData = context.getHttpRequest().getDecodedFormParameters();

        if (inputData.containsKey("cancel")) {
            context.resetFlow();
            return;
        }

        List<UserCredentialModel> credentials = new LinkedList<>();

        String code = inputData.getFirst(CredentialRepresentation.CODE);
        if (code == null) {
            Response challengeResponse = challenge(context, null);
            context.challenge(challengeResponse);
            return;
        }

        credentials.add(UserCredentialModel.code(code));

        boolean valid = context.getSession().users().validCredentials(context.getSession(), context.getRealm(), context.getUser(), credentials);

        if (valid) {
            context.success();
            return;
        }

        context.getEvent().user(context.getUser())
                .error(Errors.INVALID_USER_CREDENTIALS);
        Response challengeResponse = challenge(context, Messages.INVALID_CODE);
        context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challengeResponse);
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    protected Response challenge(AuthenticationFlowContext context, String error) {

        LoginFormsProvider forms = context.form();
        if (error != null) forms.setError(error);

        String code = Integer.toHexString((int)((2 << 24) * Math.random()));

        context.getUser().updateCredential(UserCredentialModel.code(code));

        //TODO send mail asynchronous
        EmailSenderProvider emailProvider = context.getSession().getProvider(EmailSenderProvider.class);
        try {
            emailProvider.send(context.getRealm(), context.getUser(), "Code","Generated code: " + code,"Generated code: " + code);
        } catch (EmailException e) {
            forms.setError(e.getMessage());
        }

        return forms.createLoginViaEmailCode();
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        //return session.users().configuredForCredentialType(realm.getOTPPolicy().getType(), realm, user);
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {

        if (!user.getRequiredActions().contains(UserModel.RequiredAction.VERIFY_EMAIL.name())) {
            user.addRequiredAction(UserModel.RequiredAction.VERIFY_EMAIL.name());
        }
    }


    @Override
    public void close() {
        //NOOP
    }
}