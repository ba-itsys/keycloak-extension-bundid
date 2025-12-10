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

package de.ba.oiam.keycloak.bundid.mapper;

import com.google.auto.service.AutoService;
import de.ba.oiam.keycloak.bundid.AuthnLevel;
import de.ba.oiam.keycloak.bundid.SamlAuthnRequestUpdater;
import de.ba.oiam.keycloak.bundid.extension.model.AuthenticationRequest;
import de.ba.oiam.keycloak.bundid.extension.model.RequestedAttribute;
import java.util.*;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import javax.xml.namespace.QName;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.AbstractIdentityProviderMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityProviderMapper;
import org.keycloak.broker.saml.SAMLEndpoint;
import org.keycloak.broker.saml.SAMLIdentityProviderFactory;
import org.keycloak.dom.saml.v2.assertion.AssertionType;
import org.keycloak.dom.saml.v2.assertion.AttributeStatementType;
import org.keycloak.dom.saml.v2.assertion.AttributeType;
import org.keycloak.dom.saml.v2.protocol.AuthnRequestType;
import org.keycloak.models.*;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.saml.common.constants.JBossSAMLURIConstants;
import org.keycloak.saml.common.util.StringUtil;
import org.keycloak.sessions.AuthenticationSessionModel;

@AutoService(IdentityProviderMapper.class)
public class BundIdUserSessionAttributeMapper extends AbstractIdentityProviderMapper
        implements SamlAuthnRequestUpdater {
    private static final Logger LOG = Logger.getLogger(BundIdUserSessionAttributeMapper.class);

    public static final String[] COMPATIBLE_PROVIDERS = {SAMLIdentityProviderFactory.PROVIDER_ID};

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    public static final String ATTRIBUTE_NAME = "attribute.name";
    public static final String ATTRIBUTE_FRIENDLY_NAME = "attribute.friendly.name";
    public static final String ATTRIBUTE_OID = "attribute.oid";
    public static final String ATTRIBUTE_REQUIRED = "attribute.required";
    public static final String ATTRIBUTE_NAME_FORMAT = "attribute.name.format";
    public static final String SESSION_ATTRIBUTE_PREFIX = "session.attribute.prefix";
    public static final String SESSION_ATTRIBUTE = "session.attribute";
    public static final String SESSION_ATTRIBUTE_EXCLUDE_FROM_AUTOMAPPER = "session.attribute.excludeFromAutomapper";
    private static final Set<IdentityProviderSyncMode> IDENTITY_PROVIDER_SYNC_MODES =
            new HashSet<>(Arrays.asList(IdentityProviderSyncMode.values()));

    public static final List<String> NAME_FORMATS = Arrays.asList(
            JBossSAMLURIConstants.ATTRIBUTE_FORMAT_BASIC.name(),
            JBossSAMLURIConstants.ATTRIBUTE_FORMAT_URI.name(),
            JBossSAMLURIConstants.ATTRIBUTE_FORMAT_UNSPECIFIED.name());
    public static final QName TRUST_LEVEL_QNAME =
            new QName("https://www.akdb.de/request/2018/09", "TrustLevel", "akdb");

    public static final String BUNDID_SESSION_ATTRIBUTE_PREFIX = "ba.bundid_prop_";
    public static final String BUNDID_SESSION_ATTRIBUTE_PREFIX_EXCLUDE_FROM_AUTOMAPPER = "ba.";
    public static final String VERIFIED_LEVEL_SUFFIX = "-verified-level";

    static {
        ProviderConfigProperty property;
        property = new ProviderConfigProperty();
        property.setName(ATTRIBUTE_NAME);
        property.setLabel("Attribute Name");
        property.setHelpText(
                "Name of attribute to search for in assertion.  You can leave this blank and specify a friendly name instead.");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        configProperties.add(property);
        property = new ProviderConfigProperty();
        property.setName(ATTRIBUTE_FRIENDLY_NAME);
        property.setLabel("Friendly Name");
        property.setHelpText(
                "Friendly name of attribute to search for in assertion.  You can leave this blank and specify a name instead.");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        configProperties.add(property);
        property = new ProviderConfigProperty();
        property.setName(ATTRIBUTE_OID);
        property.setLabel("OID");
        property.setHelpText("Attribute-OID for RequestedAttributes.Check BundID-Documentation.");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        configProperties.add(property);
        property = new ProviderConfigProperty();
        property.setName(ATTRIBUTE_REQUIRED);
        property.setLabel("Required?");
        property.setHelpText("Als Required-Attribut bei BundID anfordern.");
        property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        property.setDefaultValue(false);
        configProperties.add(property);
        property = new ProviderConfigProperty();
        property.setName(ATTRIBUTE_NAME_FORMAT);
        property.setLabel("Name Format");
        property.setHelpText(
                "Name format of attribute to specify in the RequestedAttribute element. Default to basic format.");
        property.setType(ProviderConfigProperty.LIST_TYPE);
        property.setOptions(NAME_FORMATS);
        property.setDefaultValue(JBossSAMLURIConstants.ATTRIBUTE_FORMAT_BASIC.name());
        configProperties.add(property);
        property = new ProviderConfigProperty();
        property.setName(SESSION_ATTRIBUTE);
        property.setLabel("Session Attribute Name");
        property.setHelpText("Session attribute name to store saml attribute.");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        configProperties.add(property);
        property = new ProviderConfigProperty();
        property.setName(SESSION_ATTRIBUTE_PREFIX);
        property.setLabel("Session Attribute Prefix");
        property.setHelpText("Optional custom prefix.");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        configProperties.add(property);
        property = new ProviderConfigProperty();
        property.setName(SESSION_ATTRIBUTE_EXCLUDE_FROM_AUTOMAPPER);
        property.setLabel("Session Attribute exclude from automapping.");
        property.setHelpText("Exclude from automatic mapping with BundIdProtocolMapper.");
        property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        property.setDefaultValue(false);
        configProperties.add(property);
    }

    public static final String PROVIDER_ID = "saml-bundid-session-attribute-idp-mapper";

    @Override
    public boolean supportsSyncMode(IdentityProviderSyncMode syncMode) {
        return IDENTITY_PROVIDER_SYNC_MODES.contains(syncMode);
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String[] getCompatibleProviders() {
        return COMPATIBLE_PROVIDERS;
    }

    @Override
    public String getDisplayCategory() {
        return "BundID Session Attribute Importer";
    }

    @Override
    public String getDisplayType() {
        return "BundID Session Attribute Importer";
    }

    @Override
    public void preprocessFederatedIdentity(
            KeycloakSession session,
            RealmModel realm,
            IdentityProviderMapperModel mapperModel,
            BrokeredIdentityContext context) {
        setSessionAttribute(session, mapperModel, context);
    }

    @Override
    public void updateBrokeredUser(
            KeycloakSession session,
            RealmModel realm,
            UserModel user,
            IdentityProviderMapperModel mapperModel,
            BrokeredIdentityContext context) {
        setSessionAttribute(session, mapperModel, context);
    }

    @Override
    public void importNewUser(
            KeycloakSession session,
            RealmModel realm,
            UserModel user,
            IdentityProviderMapperModel mapperModel,
            BrokeredIdentityContext context) {
        setSessionAttribute(session, mapperModel, context);
    }

    private void setSessionAttribute(
            KeycloakSession session, IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        String attribute = mapperModel.getConfig().get(SESSION_ATTRIBUTE);
        if (StringUtil.isNullOrEmpty(attribute)) {
            return;
        }

        boolean excludeFromAutomapper = Boolean.parseBoolean(
                mapperModel.getConfig().getOrDefault(SESSION_ATTRIBUTE_EXCLUDE_FROM_AUTOMAPPER, "false"));
        String attributeName = getAttributeNameFromMapperModel(mapperModel);

        List<String> attributeValuesInContext = findAttributeValuesInContext(attributeName, context);
        if (attributeValuesInContext != null && !attributeValuesInContext.isEmpty()) {
            if (attributeValuesInContext.size() > 1) {
                LOG.warnf("Attribute '%s' has more than one value. Discarding all but the first.", attributeName);
            }

            String prefix = mapperModel
                    .getConfig()
                    .getOrDefault(
                            SESSION_ATTRIBUTE_PREFIX,
                            excludeFromAutomapper
                                    ? BUNDID_SESSION_ATTRIBUTE_PREFIX_EXCLUDE_FROM_AUTOMAPPER
                                    : BUNDID_SESSION_ATTRIBUTE_PREFIX);
            updateSession(session, context, prefix + attribute, attributeValuesInContext.get(0), false);
            findStorkValueForAttribute(attributeName, context)
                    .ifPresent(stork -> updateSession(
                            session, context.getAuthenticationSession(), prefix + attribute, stork, true));
        }
    }

    // Extension point for custom behavior
    protected void updateSession(
            KeycloakSession session, BrokeredIdentityContext context, String key, String value, boolean isStorkLevel) {
        updateSession(session, context.getAuthenticationSession(), key, value, isStorkLevel);
    }

    @Deprecated
    protected void updateSession(
            KeycloakSession session,
            AuthenticationSessionModel authSession,
            String key,
            String value,
            boolean isStorkLevel) {
        if (isStorkLevel) {
            authSession.setUserSessionNote(key + VERIFIED_LEVEL_SUFFIX, value);
        } else {
            authSession.setUserSessionNote(key, value);
        }
    }

    private String getAttributeNameFromMapperModel(IdentityProviderMapperModel mapperModel) {
        String attributeName = mapperModel.getConfig().get(ATTRIBUTE_NAME);
        if (attributeName == null) {
            attributeName = mapperModel.getConfig().get(ATTRIBUTE_FRIENDLY_NAME);
        }
        return attributeName;
    }

    private static Predicate<AttributeStatementType.ASTChoiceType> elementWithTrustLevel() {
        return attributeType ->
                attributeType.getAttribute().getOtherAttributes().containsKey(TRUST_LEVEL_QNAME);
    }

    private static Predicate<AttributeStatementType.ASTChoiceType> elementWith(String attributeName) {
        return attributeType -> {
            AttributeType attribute = attributeType.getAttribute();
            String aName = attribute.getName();
            String aFriendlyName = attribute.getFriendlyName();
            return ((aName != null && aName.equalsIgnoreCase(attributeName))
                    || (aFriendlyName != null && aFriendlyName.equalsIgnoreCase(attributeName)));
        };
    }

    private Optional<String> findStorkValueForAttribute(String attributeName, BrokeredIdentityContext context) {
        AssertionType assertion = (AssertionType) context.getContextData().get(SAMLEndpoint.SAML_ASSERTION);

        return assertion.getAttributeStatements().stream()
                .flatMap(statement -> statement.getAttributes().stream())
                .filter(elementWith(attributeName))
                .filter(elementWithTrustLevel())
                .map(attributeType ->
                        attributeType.getAttribute().getOtherAttributes().get(TRUST_LEVEL_QNAME))
                .flatMap(trustLevel -> Optional.ofNullable(AuthnLevel.fromAkdbTrustlevel(trustLevel)).stream())
                .map(AuthnLevel::getFullname)
                .findFirst();
    }

    private List<String> findAttributeValuesInContext(String attributeName, BrokeredIdentityContext context) {
        AssertionType assertion = (AssertionType) context.getContextData().get(SAMLEndpoint.SAML_ASSERTION);

        return assertion.getAttributeStatements().stream()
                .flatMap(statement -> statement.getAttributes().stream())
                .filter(elementWith(attributeName))
                .flatMap(attributeType -> attributeType.getAttribute().getAttributeValue().stream())
                .filter(Objects::nonNull)
                .map(Object::toString)
                .collect(Collectors.toList());
    }

    @Override
    public String getHelpText() {
        return "Import declared saml attribute if it exists in assertion into the specified session attribute.";
    }

    @Override
    public void updateRequest(IdentityProviderMapperModel mapperModel, AuthnRequestType authnRequest) {
        String attributeOid = mapperModel.getConfig().get(ATTRIBUTE_OID);
        boolean required = Boolean.parseBoolean(mapperModel.getConfig().get(ATTRIBUTE_REQUIRED));

        if (attributeOid == null) {
            return;
        }

        AuthenticationRequest existingExtension = AuthenticationRequest.readExisting(authnRequest);

        RequestedAttribute requestedAttribute = new RequestedAttribute();
        requestedAttribute.setName(attributeOid);
        requestedAttribute.setRequiredAttribute(required);

        if (existingExtension != null) {
            existingExtension.getRequestedAttributes().getRequestedAttributes().add(requestedAttribute);
            existingExtension.addOrUpdate(authnRequest);
        } else {
            AuthenticationRequest authenticationRequest = new AuthenticationRequest();
            authenticationRequest
                    .getRequestedAttributes()
                    .getRequestedAttributes()
                    .add(requestedAttribute);

            authenticationRequest.addOrUpdate(authnRequest);
        }
    }
}
