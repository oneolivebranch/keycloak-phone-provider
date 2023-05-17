package cc.coopersoft.keycloak.phone.authentication.authenticators.browser;

import cc.coopersoft.keycloak.phone.CountryCodes;
import cc.coopersoft.keycloak.phone.Utils;
import cc.coopersoft.keycloak.phone.authentication.forms.SupportPhonePages;
import cc.coopersoft.keycloak.phone.credential.PhoneOtpCredentialModel;
import cc.coopersoft.keycloak.phone.credential.PhoneOtpCredentialProvider;
import cc.coopersoft.keycloak.phone.credential.PhoneOtpCredentialProviderFactory;
import cc.coopersoft.keycloak.phone.providers.exception.PhoneNumberInvalidException;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.validation.Validation;
import org.keycloak.userprofile.UserProfile;
import org.keycloak.userprofile.UserProfileContext;
import org.keycloak.userprofile.UserProfileProvider;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.net.URI;
import java.util.Collections;


public class PhoneLoginAndAutoCreateUserForm extends UsernamePasswordForm {
    private void createCredential(AuthenticationFlowContext context, String username, UserModel user) {
        PhoneOtpCredentialProvider ocp = (PhoneOtpCredentialProvider) context.getSession()
                .getProvider(CredentialProvider.class, PhoneOtpCredentialProviderFactory.PROVIDER_ID);
        String code = context.getHttpRequest().getDecodedFormParameters().getFirst(SupportPhonePages.FIELD_VERIFICATION_CODE);
        ocp.createCredential(context.getRealm(), user,
                PhoneOtpCredentialModel.create(username, code, Utils.getOtpExpires(context.getSession())));
    }

    // Copy from PhoneUsernamePasswordForm
    @Override
    protected boolean validateForm(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        UserModel user = getUser(context, formData);
        if (user == null) {
            user = createUserModel(formData, context);
        }
        return new PhoneUsernamePasswordForm().validateUser(context, user, formData);
    }

    // Copy from PhoneUsernamePasswordForm
    private UserModel getUser(AuthenticationFlowContext context, MultivaluedMap<String, String> inputData) {
        if (isUserAlreadySetBeforeUsernamePasswordAuth(context)) {
            // Get user from the authentication context in case he was already set before this authenticator
            UserModel user = context.getUser();
            testInvalidUser(context, user);
            return user;
        } else {
            // Normal login. In this case this authenticator is supposed to establish identity of the user from the provided username
            context.clearUser();
            return getUserFromForm(context, inputData);
        }
    }

    // Copy from PhoneUsernamePasswordForm (custom validate phone Number and create user)
    private UserModel getUserFromForm(AuthenticationFlowContext context, MultivaluedMap<String, String> inputData) {
        String username = inputData.getFirst(Details.USERNAME);
        KeycloakSession session = context.getSession();
        if (username == null) {
            context.getEvent().error(Errors.USER_NOT_FOUND);
            Response challengeResponse = challenge(context, getDefaultChallengeMessage(context), Validation.FIELD_USERNAME);
            context.failureChallenge(AuthenticationFlowError.INVALID_USER, challengeResponse);
            return null;
        }
        try {
            Utils.canonicalizePhoneNumber(session, username);
            username = standardizePhoneNumber(session, username);
        } catch (PhoneNumberInvalidException e) {
            context.getEvent().error(Errors.INVALID_INPUT);
            Response challengeResponse = challenge(context, e.getErrorType().message(), Validation.FIELD_USERNAME);
            context.failureChallenge(AuthenticationFlowError.INVALID_USER, challengeResponse);
            return null;
        }
        context.getEvent().detail(Details.USERNAME, username);
        context.getAuthenticationSession().setAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, username);

        UserModel user = null;
        try {
            user = KeycloakModelUtils.findUserByNameOrEmail(session, context.getRealm(), username);
        } catch (ModelDuplicateException mde) {
            ServicesLogger.LOGGER.modelDuplicateException(mde);
            // Could happen during federation import
            if (mde.getDuplicateFieldName() != null && mde.getDuplicateFieldName().equals(UserModel.EMAIL)) {
                setDuplicateUserChallenge(context, Errors.EMAIL_IN_USE, Messages.EMAIL_EXISTS, AuthenticationFlowError.INVALID_USER);
            } else {
                setDuplicateUserChallenge(context, Errors.USERNAME_IN_USE, Messages.USERNAME_EXISTS, AuthenticationFlowError.INVALID_USER);
            }
            return user;
        }
        return user;
    }

    private UserModel createUserModel(MultivaluedMap<String, String> inputData, AuthenticationFlowContext context) {
        String username = inputData.getFirst(Details.USERNAME);
        username = standardizePhoneNumber(context.getSession(), username);
        UserModel user;
        inputData.put(Details.USERNAME, Collections.singletonList(username));
        UserProfileProvider profileProvider = context.getSession().getProvider(UserProfileProvider.class);
        UserProfile profile = profileProvider.create(UserProfileContext.REGISTRATION_USER_CREATION, inputData);
        user = profile.create();
        user.setEnabled(true);
        user.setAttribute("phoneNumber", Collections.singletonList(username));
        createCredential(context, username, user);
        return user;
    }

    private String standardizePhoneNumber(KeycloakSession session, String phoneNumber) {
        phoneNumber = phoneNumber.trim();
        String defaultCountryCode = CountryCodes.getCode(Utils.defaultRegion(session));
        if (phoneNumber.startsWith("0")) {
            return defaultCountryCode + phoneNumber.substring(1);
        } else if (phoneNumber.startsWith(defaultCountryCode)) {
            return phoneNumber;
        } else {
            return defaultCountryCode + phoneNumber;
        }
    }

    // Copy from UsernameForm
    @Override
    protected Response challenge(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        removeCookieSmsOtpAnswered(context);
        LoginFormsProvider forms = context.form();
        if (!formData.isEmpty()) forms.setFormData(formData);
        return forms.createLoginUsername();
    }

    private void removeCookieSmsOtpAnswered(AuthenticationFlowContext context) {
        URI uri = context.getUriInfo()
                .getBaseUriBuilder()
                .path("realms")
                .path(context.getRealm().getName())
                .build();
        new SmsOtpMfaAuthenticator().
                addCookie(context, "SMS_OTP_ANSWERED", null,
                        uri.getRawPath(),
                        null, null,
                        0,
                        false, true);
    }

    // Copy from UsernameForm
    @Override
    protected Response createLoginForm(LoginFormsProvider form) {
        return form.createLoginUsername();
    }

    @Override
    protected String getDefaultChallengeMessage(AuthenticationFlowContext context) {
        return Messages.INVALID_USERNAME;
    }
}
