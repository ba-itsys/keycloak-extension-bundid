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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.IDToken;

class BundIdProtocolMapperTest {

    private static final String PREFIX = BundIdUserSessionAttributeMapper.BUNDID_SESSION_ATTRIBUTE_PREFIX;

    private final BundIdProtocolMapper mapper = new BundIdProtocolMapper();

    @Test
    void mapsAllBundIdNotesToTokenClaimsWithoutMutatingMapperModel() {
        ProtocolMapperModel model = createModel();
        Map<String, String> originalConfig = new HashMap<>(model.getConfig());
        UserSessionModel userSession = userSessionWithNotes(
                Map.of(PREFIX + "givenName", "Erika", PREFIX + "surname", "Mustermann", "other", "ignored"));

        IDToken token = new IDToken();
        mapper.setClaim(token, model, userSession);

        assertEquals("Erika", token.getOtherClaims().get("givenName"));
        assertEquals("Mustermann", token.getOtherClaims().get("surname"));
        assertEquals(2, token.getOtherClaims().size());
        assertEquals(originalConfig, model.getConfig());
    }

    @Test
    void mapsAllBundIdNotesToAccessTokenResponseWithoutMutatingMapperModel() {
        ProtocolMapperModel model = createModel();
        Map<String, String> originalConfig = new HashMap<>(model.getConfig());
        UserSessionModel userSession = userSessionWithNotes(
                Map.of(PREFIX + "givenName", "Erika", PREFIX + "surname", "Mustermann", "other", "ignored"));

        AccessTokenResponse response = new AccessTokenResponse();
        mapper.setClaim(response, model, userSession, null, null);

        assertEquals("Erika", response.getOtherClaims().get("givenName"));
        assertEquals("Mustermann", response.getOtherClaims().get("surname"));
        assertEquals(2, response.getOtherClaims().size());
        assertEquals(originalConfig, model.getConfig());
    }

    private static ProtocolMapperModel createModel() {
        ProtocolMapperModel model = new ProtocolMapperModel();
        model.setName("bundid");
        model.setProtocolMapper(BundIdProtocolMapper.PROVIDER_ID);
        Map<String, String> config = new HashMap<>();
        config.put(OIDCAttributeMapperHelper.INCLUDE_IN_ID_TOKEN, "true");
        config.put(OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN_RESPONSE, "true");
        model.setConfig(config);
        return model;
    }

    private static UserSessionModel userSessionWithNotes(Map<String, String> notes) {
        UserSessionModel userSession = mock(UserSessionModel.class);
        when(userSession.getNotes()).thenReturn(notes);
        return userSession;
    }
}
