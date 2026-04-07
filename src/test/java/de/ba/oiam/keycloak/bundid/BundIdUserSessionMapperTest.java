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

import de.ba.oiam.keycloak.bundid.extension.model.AuthenticationRequest;
import de.ba.oiam.keycloak.bundid.mapper.BundIdUserSessionAttributeMapper;
import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.Unmarshaller;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import org.junit.jupiter.api.Test;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.saml.SAMLEndpoint;
import org.keycloak.dom.saml.v2.assertion.AssertionType;
import org.keycloak.dom.saml.v2.assertion.AttributeStatementType;
import org.keycloak.dom.saml.v2.assertion.AttributeType;
import org.keycloak.dom.saml.v2.protocol.AuthnRequestType;
import org.keycloak.models.ClientModel;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.w3c.dom.Node;

public class BundIdUserSessionMapperTest {
    @Test
    void addsStorkAttribute() throws DatatypeConfigurationException {
        AssertionType samlAssertion =
                new AssertionType("response", DatatypeFactory.newInstance().newXMLGregorianCalendar());
        AttributeStatementType attributeStatement = new AttributeStatementType();
        AttributeType attribute = new AttributeType("attrName");
        attribute.getOtherAttributes().put(BundIdUserSessionAttributeMapper.TRUST_LEVEL_QNAME, "SUBSTANTIELL");
        attribute.addAttributeValue("testValue");
        attributeStatement.addAttribute(new AttributeStatementType.ASTChoiceType(attribute));
        samlAssertion.addStatement(attributeStatement);
        BrokeredIdentityContext context = createBrokeredIdentityContext();
        context.getContextData().put(SAMLEndpoint.SAML_ASSERTION, samlAssertion);
        TestAuthenticationSessionModel authenticationSession = new TestAuthenticationSessionModel();
        context.setAuthenticationSession(authenticationSession);

        IdentityProviderMapperModel mapperModel = new IdentityProviderMapperModel();
        mapperModel.setConfig(new HashMap<>());
        mapperModel.getConfig().put(BundIdUserSessionAttributeMapper.SESSION_ATTRIBUTE, "targetAttribute");
        mapperModel.getConfig().put(BundIdUserSessionAttributeMapper.ATTRIBUTE_NAME, "attrName");

        BundIdUserSessionAttributeMapper mapper = new BundIdUserSessionAttributeMapper();
        mapper.importNewUser(null, null, null, mapperModel, context);

        assertEquals(
                "testValue",
                authenticationSession
                        .getUserSessionNotes()
                        .get(BundIdUserSessionAttributeMapper.BUNDID_SESSION_ATTRIBUTE_PREFIX + "targetAttribute"));
        assertEquals(
                AuthnLevel.STORK3.getFullname(),
                authenticationSession
                        .getUserSessionNotes()
                        .get(BundIdUserSessionAttributeMapper.BUNDID_SESSION_ATTRIBUTE_PREFIX
                                + "targetAttribute-verified-level"));
    }

    @Test
    void customPrefix() throws DatatypeConfigurationException {
        AssertionType samlAssertion =
                new AssertionType("response", DatatypeFactory.newInstance().newXMLGregorianCalendar());
        AttributeStatementType attributeStatement = new AttributeStatementType();
        AttributeType attribute = new AttributeType("attrName");
        attribute.getOtherAttributes().put(BundIdUserSessionAttributeMapper.TRUST_LEVEL_QNAME, "SUBSTANTIELL");
        attribute.addAttributeValue("testValue");
        attributeStatement.addAttribute(new AttributeStatementType.ASTChoiceType(attribute));
        samlAssertion.addStatement(attributeStatement);
        BrokeredIdentityContext context = createBrokeredIdentityContext();
        context.getContextData().put(SAMLEndpoint.SAML_ASSERTION, samlAssertion);
        TestAuthenticationSessionModel authenticationSession = new TestAuthenticationSessionModel();
        context.setAuthenticationSession(authenticationSession);

        IdentityProviderMapperModel mapperModel = new IdentityProviderMapperModel();
        mapperModel.setConfig(new HashMap<>());
        mapperModel.getConfig().put(BundIdUserSessionAttributeMapper.SESSION_ATTRIBUTE, "targetAttribute");
        mapperModel.getConfig().put(BundIdUserSessionAttributeMapper.SESSION_ATTRIBUTE_PREFIX, "ba.");
        mapperModel.getConfig().put(BundIdUserSessionAttributeMapper.ATTRIBUTE_NAME, "attrName");

        BundIdUserSessionAttributeMapper mapper = new BundIdUserSessionAttributeMapper();
        mapper.importNewUser(null, null, null, mapperModel, context);

        assertEquals("testValue", authenticationSession.getUserSessionNotes().get("ba.targetAttribute"));
        assertEquals(
                AuthnLevel.STORK3.getFullname(),
                authenticationSession.getUserSessionNotes().get("ba.targetAttribute-verified-level"));
    }

    @Test
    void addsAttributeRequest() throws DatatypeConfigurationException, JAXBException {
        AssertionType samlAssertion =
                new AssertionType("response", DatatypeFactory.newInstance().newXMLGregorianCalendar());
        AttributeStatementType attributeStatement = new AttributeStatementType();
        AttributeType attribute = new AttributeType("attrName");
        attribute.getOtherAttributes().put(BundIdUserSessionAttributeMapper.TRUST_LEVEL_QNAME, "SUBSTANTIELL");
        attribute.addAttributeValue("testValue");
        attributeStatement.addAttribute(new AttributeStatementType.ASTChoiceType(attribute));
        samlAssertion.addStatement(attributeStatement);
        BrokeredIdentityContext context = createBrokeredIdentityContext();
        context.getContextData().put(SAMLEndpoint.SAML_ASSERTION, samlAssertion);
        TestAuthenticationSessionModel authenticationSession = new TestAuthenticationSessionModel();
        context.setAuthenticationSession(authenticationSession);

        IdentityProviderMapperModel mapperModel = new IdentityProviderMapperModel();
        mapperModel.setConfig(new HashMap<>());
        mapperModel.getConfig().put(BundIdUserSessionAttributeMapper.SESSION_ATTRIBUTE, "targetAttribute");
        mapperModel.getConfig().put(BundIdUserSessionAttributeMapper.ATTRIBUTE_NAME, "attrName");
        mapperModel.getConfig().put(BundIdUserSessionAttributeMapper.ATTRIBUTE_OID, "attrOid");
        mapperModel.getConfig().put(BundIdUserSessionAttributeMapper.ATTRIBUTE_REQUIRED, "true");

        BundIdUserSessionAttributeMapper mapper = new BundIdUserSessionAttributeMapper();
        AuthnRequestType request =
                new AuthnRequestType("request", DatatypeFactory.newInstance().newXMLGregorianCalendar());
        mapper.updateRequest(mapperModel, request);

        assertEquals(1, request.getExtensions().getAny().size());

        JAXBContext jaxbContext = JAXBContext.newInstance(AuthenticationRequest.class);
        Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
        AuthenticationRequest authenticationRequest = (AuthenticationRequest)
                unmarshaller.unmarshal((Node) request.getExtensions().getAny().get(0));

        assertEquals(
                "attrOid",
                authenticationRequest
                        .getRequestedAttributes()
                        .getRequestedAttributes()
                        .get(0)
                        .getName());
    }

    @Test
    void multipleAttributeRequests() throws DatatypeConfigurationException, JAXBException {
        AssertionType samlAssertion =
                new AssertionType("response", DatatypeFactory.newInstance().newXMLGregorianCalendar());
        AttributeStatementType attributeStatement = new AttributeStatementType();
        AttributeType attribute1 = new AttributeType("attrName");
        attribute1.getOtherAttributes().put(BundIdUserSessionAttributeMapper.TRUST_LEVEL_QNAME, "SUBSTANTIELL");
        attribute1.addAttributeValue("testValue");
        AttributeType attribute2 = new AttributeType("attrName2");
        attribute2.getOtherAttributes().put(BundIdUserSessionAttributeMapper.TRUST_LEVEL_QNAME, "SUBSTANTIELL");
        attribute2.addAttributeValue("testValue");
        attributeStatement.addAttribute(new AttributeStatementType.ASTChoiceType(attribute1));
        samlAssertion.addStatement(attributeStatement);
        BrokeredIdentityContext context = createBrokeredIdentityContext();
        context.getContextData().put(SAMLEndpoint.SAML_ASSERTION, samlAssertion);
        TestAuthenticationSessionModel authenticationSession = new TestAuthenticationSessionModel();
        context.setAuthenticationSession(authenticationSession);

        IdentityProviderMapperModel mapperModel = new IdentityProviderMapperModel();
        mapperModel.setConfig(new HashMap<>());
        mapperModel.getConfig().put(BundIdUserSessionAttributeMapper.SESSION_ATTRIBUTE, "targetAttribute");
        mapperModel.getConfig().put(BundIdUserSessionAttributeMapper.ATTRIBUTE_NAME, "attrName");
        mapperModel.getConfig().put(BundIdUserSessionAttributeMapper.ATTRIBUTE_OID, "attrOid");
        mapperModel.getConfig().put(BundIdUserSessionAttributeMapper.ATTRIBUTE_REQUIRED, "true");

        BundIdUserSessionAttributeMapper mapper = new BundIdUserSessionAttributeMapper();
        AuthnRequestType request =
                new AuthnRequestType("request", DatatypeFactory.newInstance().newXMLGregorianCalendar());
        mapper.updateRequest(mapperModel, request);
        mapperModel.getConfig().put(BundIdUserSessionAttributeMapper.ATTRIBUTE_NAME, "attrName2");
        mapper.updateRequest(mapperModel, request);

        assertEquals(1, request.getExtensions().getAny().size());

        JAXBContext jaxbContext = JAXBContext.newInstance(AuthenticationRequest.class);
        Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
        AuthenticationRequest authenticationRequest = (AuthenticationRequest)
                unmarshaller.unmarshal((Node) request.getExtensions().getAny().get(0));

        assertEquals(
                2,
                authenticationRequest
                        .getRequestedAttributes()
                        .getRequestedAttributes()
                        .size());
    }

    private static BrokeredIdentityContext createBrokeredIdentityContext() {
        IdentityProviderModel identityProviderModel = new IdentityProviderModel();
        identityProviderModel.setEnabled(true);
        return new BrokeredIdentityContext("test", identityProviderModel);
    }

    private static class TestAuthenticationSessionModel implements AuthenticationSessionModel {
        private Map<String, String> userSessionNotes = new HashMap<>();

        @Override
        public void setUserSessionNote(String name, String value) {
            userSessionNotes.put(name, value);
        }

        @Override
        public Map<String, String> getUserSessionNotes() {
            return userSessionNotes;
        }

        @Override
        public String getTabId() {
            return null;
        }

        @Override
        public RootAuthenticationSessionModel getParentSession() {
            return null;
        }

        @Override
        public Map<String, ExecutionStatus> getExecutionStatus() {
            return null;
        }

        @Override
        public void setExecutionStatus(String authenticator, ExecutionStatus status) {}

        @Override
        public void clearExecutionStatus() {}

        @Override
        public UserModel getAuthenticatedUser() {
            return null;
        }

        @Override
        public void setAuthenticatedUser(UserModel user) {}

        @Override
        public Set<String> getRequiredActions() {
            return null;
        }

        @Override
        public void addRequiredAction(String action) {}

        @Override
        public void removeRequiredAction(String action) {}

        @Override
        public void addRequiredAction(UserModel.RequiredAction action) {}

        @Override
        public void removeRequiredAction(UserModel.RequiredAction action) {}

        @Override
        public void clearUserSessionNotes() {}

        @Override
        public String getAuthNote(String name) {
            return null;
        }

        @Override
        public void setAuthNote(String name, String value) {}

        @Override
        public void removeAuthNote(String name) {}

        @Override
        public void clearAuthNotes() {}

        @Override
        public String getClientNote(String name) {
            return null;
        }

        @Override
        public void setClientNote(String name, String value) {}

        @Override
        public void removeClientNote(String name) {}

        @Override
        public Map<String, String> getClientNotes() {
            return null;
        }

        @Override
        public void clearClientNotes() {}

        @Override
        public Set<String> getClientScopes() {
            return null;
        }

        @Override
        public void setClientScopes(Set<String> clientScopes) {}

        @Override
        public String getRedirectUri() {
            return null;
        }

        @Override
        public void setRedirectUri(String uri) {}

        @Override
        public RealmModel getRealm() {
            return null;
        }

        @Override
        public ClientModel getClient() {
            return null;
        }

        @Override
        public String getAction() {
            return null;
        }

        @Override
        public void setAction(String action) {}

        @Override
        public String getProtocol() {
            return null;
        }

        @Override
        public void setProtocol(String method) {}
    }
}
