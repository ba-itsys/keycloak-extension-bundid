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

import static org.junit.jupiter.api.Assertions.assertNotNull;

import de.ba.oiam.keycloak.bundid.mapper.BundIdUserSessionAttributeMapper;
import de.ba.oiam.keycloak.bundid.mapper.RetrievalTimestampAttributeMapper;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.ClientModel;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;

public class RetrievalTimestampAttributeMapperTest {
    @Test
    void addsTimestamp() {
        BrokeredIdentityContext context = new BrokeredIdentityContext("test", null);
        TestAuthenticationSessionModel authenticationSession = new TestAuthenticationSessionModel();
        context.setAuthenticationSession(authenticationSession);

        IdentityProviderMapperModel mapperModel = new IdentityProviderMapperModel();
        mapperModel.setConfig(new HashMap<>());
        mapperModel.getConfig().put(BundIdUserSessionAttributeMapper.SESSION_ATTRIBUTE, "targetAttribute");

        RetrievalTimestampAttributeMapper mapper = new RetrievalTimestampAttributeMapper();
        mapper.importNewUser(null, null, null, mapperModel, context);

        assertNotNull(authenticationSession.getUserSessionNotes().get("targetAttribute"));
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
