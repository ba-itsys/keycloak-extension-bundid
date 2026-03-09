/*
 * Copyright 2024. IT-Systemhaus der Bundesagentur fuer Arbeit
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.ba.oiam.keycloak.bundid;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import de.ba.oiam.keycloak.bundid.extension.model.AuthenticationRequest;
import de.ba.oiam.keycloak.bundid.extension.model.AuthnMethods;
import java.net.URI;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.keycloak.Config;
import org.keycloak.dom.saml.v2.protocol.AuthnContextComparisonType;
import org.keycloak.dom.saml.v2.protocol.AuthnRequestType;
import org.keycloak.models.Constants;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.mockito.Answers;
import org.mockito.Mockito;

class SamlAuthenticationPreprocessorTest {

    @Test
    void thatProvidersAreCorrectlyWired() {
        SamlAuthenticationPreprocessorImpl underTest = new SamlAuthenticationPreprocessorImpl();
        AuthnRequestType authnRequest = new AuthnRequestType("myId", null);
        authnRequest.setAssertionConsumerServiceURL(URI.create("http://localhost:8081/bla/broker/bundid/endpoint"));

        AuthenticationSessionModel clientSession =
                Mockito.mock(AuthenticationSessionModel.class, Answers.RETURNS_DEEP_STUBS);
        when(clientSession.getClientNote(Constants.REQUESTED_LEVEL_OF_AUTHENTICATION))
                .thenReturn("4");

        AuthnRequestType expectedResult = underTest.beforeSendingLoginRequest(authnRequest, clientSession);

        assertEquals(
                AuthnContextComparisonType.MINIMUM,
                expectedResult.getRequestedAuthnContext().getComparison());
        assertEquals(
                List.of(AuthnLevel.STORK4.getFullname()),
                expectedResult.getRequestedAuthnContext().getAuthnContextClassRef());
    }

    @Test
    void preprocessorIsSkippedIfIdpDoesntMatch() {
        SamlAuthenticationPreprocessorImpl underTest = new SamlAuthenticationPreprocessorImpl();
        AuthnRequestType authnRequest = new AuthnRequestType("myId", null);
        authnRequest.setAssertionConsumerServiceURL(URI.create("http://localhost:8081/bla/broker/muk/endpoint"));

        AuthenticationSessionModel clientSession =
                Mockito.mock(AuthenticationSessionModel.class, Answers.RETURNS_DEEP_STUBS);
        when(clientSession.getClientNote(Constants.REQUESTED_LEVEL_OF_AUTHENTICATION))
                .thenReturn("4");

        AuthnRequestType expectedResult = underTest.beforeSendingLoginRequest(authnRequest, clientSession);

        assertNull(expectedResult.getRequestedAuthnContext());
        assertNull(expectedResult.getExtensions());
    }

    @Test
    void methodIsEnabledWhenListedInEnabledAuthnMethods() {
        SamlAuthenticationPreprocessorImpl underTest = createPreprocessorWithMethods("eID", null);

        AuthnRequestType result = underTest.beforeSendingLoginRequest(createBundIdAuthnRequest(), createSession());

        AuthnMethods authnMethods = getAuthnMethods(result);
        assertNotNull(authnMethods.getEid());
        assertTrue(authnMethods.getEid().isEnabled());
    }

    @Test
    void methodIsDisabledWhenListedInDisabledAuthnMethods() {
        SamlAuthenticationPreprocessorImpl underTest = createPreprocessorWithMethods(null, "eID");

        AuthnRequestType result = underTest.beforeSendingLoginRequest(createBundIdAuthnRequest(), createSession());

        AuthnMethods authnMethods = getAuthnMethods(result);
        assertNotNull(authnMethods.getEid());
        assertFalse(authnMethods.getEid().isEnabled());
    }

    @Test
    void noAuthnMethodsInExtensionWhenBothListsAreEmpty() {
        SamlAuthenticationPreprocessorImpl underTest = createPreprocessorWithMethods(null, null);

        AuthnRequestType result = underTest.beforeSendingLoginRequest(createBundIdAuthnRequest(), createSession());

        AuthenticationRequest extension = AuthenticationRequest.readExisting(result);
        AuthnMethods authnMethods = extension == null ? null : extension.getAuthnMethods();
        assertNull(authnMethods);
    }

    @Test
    void authnMethodsAndDisplayInfoBothPresentWhenBothConfigured() {
        Config.Scope config = Mockito.mock(Config.Scope.class);
        when(config.get("activeForIdp", "bundid")).thenReturn("bundid");
        when(config.get("organizationDisplayName")).thenReturn("Portal");
        when(config.get("disabledAuthnMethods")).thenReturn("FINK");
        SamlAuthenticationPreprocessorImpl underTest = new SamlAuthenticationPreprocessorImpl();
        underTest.init(config);

        AuthnRequestType result = underTest.beforeSendingLoginRequest(createBundIdAuthnRequest(), createSession());

        AuthnMethods authnMethods = getAuthnMethods(result);
        assertFalse(authnMethods.getFink().isEnabled());
        AuthenticationRequest extension = AuthenticationRequest.readExisting(result);
        assertNotNull(extension.getDisplayInformation());
        assertNotNull(extension.getDisplayInformation().getVersion());
        assertEquals(
                "Portal",
                extension
                        .getDisplayInformation()
                        .getVersion()
                        .getOrganizationDisplayName()
                        .getValue());
    }

    @Test
    void eachAuthnMethodAppearsInExtensionWhenConfigured() {
        Config.Scope config = Mockito.mock(Config.Scope.class);
        when(config.get("activeForIdp", "bundid")).thenReturn("bundid");
        when(config.get("enabledAuthnMethods")).thenReturn("Authega,eID,eIDAS,Benutzername");
        when(config.get("disabledAuthnMethods")).thenReturn("Diia,Elster,FINK");
        SamlAuthenticationPreprocessorImpl underTest = new SamlAuthenticationPreprocessorImpl();
        underTest.init(config);

        AuthnRequestType result = underTest.beforeSendingLoginRequest(createBundIdAuthnRequest(), createSession());

        AuthnMethods authnMethods = getAuthnMethods(result);
        assertTrue(authnMethods.getAuthega().isEnabled());
        assertFalse(authnMethods.getDiia().isEnabled());
        assertTrue(authnMethods.getEid().isEnabled());
        assertTrue(authnMethods.getEidas().isEnabled());
        assertFalse(authnMethods.getElster().isEnabled());
        assertFalse(authnMethods.getFink().isEnabled());
        assertTrue(authnMethods.getBenutzername().isEnabled());
    }

    @Test
    void unconfiguredAuthnMethodsAreAbsentFromExtension() {
        Config.Scope config = Mockito.mock(Config.Scope.class);
        when(config.get("activeForIdp", "bundid")).thenReturn("bundid");
        when(config.get("enabledAuthnMethods")).thenReturn("eID");
        SamlAuthenticationPreprocessorImpl underTest = new SamlAuthenticationPreprocessorImpl();
        underTest.init(config);

        AuthnRequestType result = underTest.beforeSendingLoginRequest(createBundIdAuthnRequest(), createSession());

        AuthnMethods authnMethods = getAuthnMethods(result);
        assertNotNull(authnMethods.getEid());
        assertNull(authnMethods.getFink());
        assertNull(authnMethods.getElster());
        assertNull(authnMethods.getEidas());
        assertNull(authnMethods.getAuthega());
        assertNull(authnMethods.getDiia());
        assertNull(authnMethods.getBenutzername());
    }

    @ParameterizedTest
    @ValueSource(strings = {"unknownMethod,eID", "eID,eID", "unknownMethod,eID,eID,anotherUnknown"})
    void invalidEntriesInEnabledListAreIgnoredAndEidIsEnabled(String enabledMethods) {
        SamlAuthenticationPreprocessorImpl underTest = createPreprocessorWithMethods(enabledMethods, null);

        AuthnRequestType result = underTest.beforeSendingLoginRequest(createBundIdAuthnRequest(), createSession());

        AuthnMethods authnMethods = getAuthnMethods(result);
        assertTrue(authnMethods.getEid().isEnabled());
        assertNull(authnMethods.getAuthega());
        assertNull(authnMethods.getDiia());
        assertNull(authnMethods.getEidas());
        assertNull(authnMethods.getElster());
        assertNull(authnMethods.getFink());
        assertNull(authnMethods.getBenutzername());
    }

    @ParameterizedTest
    @ValueSource(strings = {"unknownMethod,eID", "eID,eID", "unknownMethod,eID,eID,anotherUnknown"})
    void invalidEntriesInDisabledListAreIgnoredAndEidIsDisabled(String disabledMethods) {
        SamlAuthenticationPreprocessorImpl underTest = createPreprocessorWithMethods(null, disabledMethods);

        AuthnRequestType result = underTest.beforeSendingLoginRequest(createBundIdAuthnRequest(), createSession());

        AuthnMethods authnMethods = getAuthnMethods(result);
        assertFalse(authnMethods.getEid().isEnabled());
        assertNull(authnMethods.getAuthega());
        assertNull(authnMethods.getDiia());
        assertNull(authnMethods.getEidas());
        assertNull(authnMethods.getElster());
        assertNull(authnMethods.getFink());
        assertNull(authnMethods.getBenutzername());
    }

    @Test
    void enabledListTakesPrecedenceWhenMethodIsInBothLists() {
        SamlAuthenticationPreprocessorImpl underTest = createPreprocessorWithMethods("eID", "eID");

        AuthnRequestType result = underTest.beforeSendingLoginRequest(createBundIdAuthnRequest(), createSession());

        AuthnMethods authnMethods = getAuthnMethods(result);
        assertTrue(authnMethods.getEid().isEnabled());
    }

    private AuthnMethods getAuthnMethods(AuthnRequestType result) {
        AuthenticationRequest extension = AuthenticationRequest.readExisting(result);
        assertNotNull(extension);
        assertNotNull(extension.getAuthnMethods());
        return extension.getAuthnMethods();
    }

    private SamlAuthenticationPreprocessorImpl createPreprocessorWithMethods(String enabled, String disabled) {
        Config.Scope config = Mockito.mock(Config.Scope.class);
        when(config.get("activeForIdp", "bundid")).thenReturn("bundid");
        when(config.get("enabledAuthnMethods")).thenReturn(enabled);
        when(config.get("disabledAuthnMethods")).thenReturn(disabled);
        SamlAuthenticationPreprocessorImpl preprocessor = new SamlAuthenticationPreprocessorImpl();
        preprocessor.init(config);
        return preprocessor;
    }

    private AuthnRequestType createBundIdAuthnRequest() {
        AuthnRequestType authnRequest = new AuthnRequestType("myId", null);
        authnRequest.setAssertionConsumerServiceURL(URI.create("http://localhost:8081/bla/broker/bundid/endpoint"));
        return authnRequest;
    }

    private AuthenticationSessionModel createSession() {
        AuthenticationSessionModel session = Mockito.mock(AuthenticationSessionModel.class, Answers.RETURNS_DEEP_STUBS);
        when(session.getClientNote(Constants.REQUESTED_LEVEL_OF_AUTHENTICATION)).thenReturn(null);
        return session;
    }
}
