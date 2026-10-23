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

import static org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper.TOKEN_CLAIM_NAME;

import com.google.auto.service.AutoService;
import java.util.ArrayList;
import java.util.List;
import java.util.function.BiConsumer;
import org.keycloak.models.*;
import org.keycloak.protocol.ProtocolMapper;
import org.keycloak.protocol.oidc.mappers.*;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.IDToken;

@AutoService(ProtocolMapper.class)
public class BundIdProtocolMapper extends AbstractOIDCProtocolMapper
        implements OIDCAccessTokenMapper, OIDCIDTokenMapper, OIDCAccessTokenResponseMapper, UserInfoTokenMapper {

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    static {
        OIDCAttributeMapperHelper.addAttributeConfig(configProperties, UserSessionNoteMapper.class);
    }

    public static final String PROVIDER_ID = "oidc-bundid-sessionnote-mapper";

    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "BundID User Session Notes";
    }

    @Override
    public String getDisplayCategory() {
        return TOKEN_MAPPER_CATEGORY;
    }

    @Override
    public String getHelpText() {
        return "Map all BundID user session notes to token claims.";
    }

    protected void setClaim(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession) {
        forEachBundIdNote(
                mappingModel,
                userSession,
                (claimModel, value) -> OIDCAttributeMapperHelper.mapClaim(token, claimModel, value));
    }

    @Override
    protected void setClaim(
            AccessTokenResponse accessTokenResponse,
            ProtocolMapperModel mappingModel,
            UserSessionModel userSession,
            KeycloakSession keycloakSession,
            ClientSessionContext clientSessionCtx) {
        forEachBundIdNote(
                mappingModel,
                userSession,
                (claimModel, value) -> OIDCAttributeMapperHelper.mapClaim(accessTokenResponse, claimModel, value));
    }

    /**
     * The mapper model is shared (realm cache, concurrent requests), so each claim gets its own copy
     * carrying the claim name derived from the session note key.
     */
    private static void forEachBundIdNote(
            ProtocolMapperModel mappingModel,
            UserSessionModel userSession,
            BiConsumer<ProtocolMapperModel, String> claimMapper) {
        userSession.getNotes().entrySet().stream()
                .filter(e -> e.getKey().startsWith(BundIdUserSessionAttributeMapper.BUNDID_SESSION_ATTRIBUTE_PREFIX))
                .forEach(e -> {
                    ProtocolMapperModel claimModel = new ProtocolMapperModel(mappingModel);
                    claimModel
                            .getConfig()
                            .put(
                                    TOKEN_CLAIM_NAME,
                                    e.getKey()
                                            .replace(
                                                    BundIdUserSessionAttributeMapper.BUNDID_SESSION_ATTRIBUTE_PREFIX,
                                                    ""));
                    claimMapper.accept(claimModel, e.getValue());
                });
    }
}
