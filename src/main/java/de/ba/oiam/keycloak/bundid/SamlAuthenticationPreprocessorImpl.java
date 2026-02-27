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

import com.google.auto.service.AutoService;
import de.ba.oiam.keycloak.bundid.extension.model.AuthenticationRequest;
import de.ba.oiam.keycloak.bundid.extension.model.AuthnMethodEnabled;
import de.ba.oiam.keycloak.bundid.extension.model.AuthnMethods;
import de.ba.oiam.keycloak.bundid.extension.model.DisplayInformation;
import de.ba.oiam.keycloak.bundid.extension.model.DisplayInformationValue;
import de.ba.oiam.keycloak.bundid.extension.model.DisplayInformationVersion;
import java.util.Arrays;
import java.util.Collections;
import java.util.Set;
import java.util.function.BiConsumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.jboss.logging.Logger;
import org.keycloak.Config.Scope;
import org.keycloak.authentication.authenticators.util.AcrStore;
import org.keycloak.broker.provider.IdentityProviderMapper;
import org.keycloak.dom.saml.v2.protocol.AuthnContextComparisonType;
import org.keycloak.dom.saml.v2.protocol.AuthnRequestType;
import org.keycloak.dom.saml.v2.protocol.RequestedAuthnContextType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.protocol.saml.preprocessor.SamlAuthenticationPreprocessor;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.utils.StringUtil;

@AutoService(SamlAuthenticationPreprocessor.class)
public class SamlAuthenticationPreprocessorImpl implements SamlAuthenticationPreprocessor {
    // TODO: Hack to get idp name, should be provided instead...
    private static final Pattern IDP_NAME_PATTERN = Pattern.compile(".*/broker/(.+)/endpoint.*");
    private static final String ACTIVE_FOR_IDP_PROPERTY = "activeForIdp";
    private static final String ONLINE_SERVICE_ID = "onlineServiceId";
    private static final String ORGANIZATION_DISPLAY_NAME = "organizationDisplayName";
    private static final String MINIMUM_STORK_LEVEL = "minimumStorkLevel";
    private static final String ENABLED_AUTHN_METHODS = "enabledAuthnMethods";
    private static final String DISABLED_AUTHN_METHODS = "disabledAuthnMethods";

    public static final String ID = "bundid-protocol";
    private static final Logger LOG = Logger.getLogger(SamlAuthenticationPreprocessorImpl.class);

    private KeycloakSessionFactory sessionFactory;
    private String activeForIdp = "bundid";
    private String onlineServiceId = "";
    private String organizationDisplayName = "";

    private Integer minimumStorkLevel = null;
    private Set<String> enabledAuthnMethods = Collections.emptySet();
    private Set<String> disabledAuthnMethods = Collections.emptySet();

    public SamlAuthenticationPreprocessorImpl() {}

    @Override
    public void close() {}

    // Create is never actually called since Keycloak is using a shortcut here...
    @Override
    public SamlAuthenticationPreprocessor create(KeycloakSession session) {
        return this;
    }

    @Override
    public void init(Scope config) {
        activeForIdp = config.get(ACTIVE_FOR_IDP_PROPERTY, "bundid");
        onlineServiceId = config.get(ONLINE_SERVICE_ID);
        organizationDisplayName = config.get(ORGANIZATION_DISPLAY_NAME);
        minimumStorkLevel = config.getInt(MINIMUM_STORK_LEVEL);
        enabledAuthnMethods = parseMethodList(config, ENABLED_AUTHN_METHODS);
        disabledAuthnMethods = parseMethodList(config, DISABLED_AUTHN_METHODS);
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        this.sessionFactory = factory;
    }

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public AuthnRequestType beforeSendingLoginRequest(
            AuthnRequestType authnRequest, AuthenticationSessionModel authSession) {
        Matcher idpNameMatcher = IDP_NAME_PATTERN.matcher(
                authnRequest.getAssertionConsumerServiceURL().getPath());
        if (!idpNameMatcher.matches()) {
            LOG.warnf(
                    "Cannot find IDP name from consumer service URL '%s'. Preprocessor is skipped.",
                    authnRequest.getAssertionConsumerServiceURL().toString());
            return authnRequest;
        }

        String idpName = idpNameMatcher.group(1);
        if (!activeForIdp.equalsIgnoreCase(idpName)) {
            LOG.tracef(
                    "BundID preprocessor only runs for IDP with name '%s'. Got '%s'. Skipping...",
                    activeForIdp, idpName);
            return authnRequest;
        }

        AuthnLevel authnLevel = getAuthnLevel(authSession);

        if (authnLevel != null) {
            RequestedAuthnContextType requestedAuthnContext = new RequestedAuthnContextType();
            requestedAuthnContext.addAuthnContextClassRef(authnLevel.getFullname());
            requestedAuthnContext.setComparison(AuthnContextComparisonType.MINIMUM);
            authnRequest.setRequestedAuthnContext(requestedAuthnContext);
        }

        authSession.getRealm().getIdentityProviderMappersByAliasStream(idpName).forEach(model -> {
            IdentityProviderMapper idpMapper = (IdentityProviderMapper)
                    sessionFactory.getProviderFactory(IdentityProviderMapper.class, model.getIdentityProviderMapper());
            if (idpMapper instanceof SamlAuthnRequestUpdater updater) {
                updater.updateRequest(model, authnRequest);
            }
        });

        if (!StringUtil.isNullOrEmpty(onlineServiceId)
                || !StringUtil.isNullOrEmpty(organizationDisplayName)
                || hasAnyAuthnMethodConfig()) {
            updateAuthenticationRequest(authnRequest);
        }

        return SamlAuthenticationPreprocessor.super.beforeSendingLoginRequest(authnRequest, authSession);
    }

    private AuthnLevel getAuthnLevel(AuthenticationSessionModel authSession) {
        AcrStore acrStore = new AcrStore(null, authSession);
        int loa = acrStore.getRequestedLevelOfAuthentication(null);

        if (minimumStorkLevel != null) {
            loa = Math.max(loa, minimumStorkLevel);
        }

        return AuthnLevel.fromLoA(loa);
    }

    private void updateAuthenticationRequest(AuthnRequestType authnRequest) {
        AuthenticationRequest extension = AuthenticationRequest.readExisting(authnRequest);
        if (extension == null) {
            extension = new AuthenticationRequest();
        }

        if (!StringUtil.isNullOrEmpty(onlineServiceId) || !StringUtil.isNullOrEmpty(organizationDisplayName)) {
            DisplayInformation displayInformation = new DisplayInformation();
            displayInformation.setVersion(new DisplayInformationVersion());
            if (!StringUtil.isNullOrEmpty(onlineServiceId)) {
                DisplayInformationValue value = new DisplayInformationValue();
                value.setValue(onlineServiceId);
                displayInformation.getVersion().setOnlineServiceId(value);
            }
            if (!StringUtil.isNullOrEmpty(organizationDisplayName)) {
                DisplayInformationValue value = new DisplayInformationValue();
                value.setValue(organizationDisplayName);
                displayInformation.getVersion().setOrganizationDisplayName(value);
            }
            extension.setDisplayInformation(displayInformation);
        }

        if (hasAnyAuthnMethodConfig()) {
            extension.setAuthnMethods(getAuthnMethods());
        }

        extension.addOrUpdate(authnRequest);
    }

    private AuthnMethods getAuthnMethods() {
        var authnMethods = new AuthnMethods();
        for (Method method : Method.values()) {
            if (enabledAuthnMethods.contains(method.key)) {
                method.setter.accept(authnMethods, new AuthnMethodEnabled(true));
            } else if (disabledAuthnMethods.contains(method.key)) {
                method.setter.accept(authnMethods, new AuthnMethodEnabled(false));
            }
        }
        return authnMethods;
    }

    private boolean hasAnyAuthnMethodConfig() {
        return !enabledAuthnMethods.isEmpty() || !disabledAuthnMethods.isEmpty();
    }

    private static Set<String> parseMethodList(Scope config, String key) {
        String value = config.get(key);
        if (value == null || value.isBlank()) {
            return Collections.emptySet();
        }
        return Arrays.stream(value.split(","))
                .map(s -> s.trim().toLowerCase())
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toSet());
    }

    private enum Method {
        AUTHEGA("authega", AuthnMethods::setAuthega),
        DIIA("diia", AuthnMethods::setDiia),
        EID("eid", AuthnMethods::setEid),
        EIDAS("eidas", AuthnMethods::setEidas),
        ELSTER("elster", AuthnMethods::setElster),
        FINK("fink", AuthnMethods::setFink),
        BENUTZERNAME("benutzername", AuthnMethods::setBenutzername);

        final String key;
        final BiConsumer<AuthnMethods, AuthnMethodEnabled> setter;

        Method(String key, BiConsumer<AuthnMethods, AuthnMethodEnabled> setter) {
            this.key = key;
            this.setter = setter;
        }
    }
}
