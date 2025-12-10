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
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityProviderMapper;
import org.keycloak.models.*;

/**
 * {@link BundIdUserSessionAttributeMapper} which also adds the mapped value to {@link BrokeredIdentityContext}
 */
@AutoService(IdentityProviderMapper.class)
public class BundIdUserSessionEmailMapper extends BundIdUserSessionAttributeMapper {

    public static final String PROVIDER_ID = "saml-bundid-session-email-idp-mapper";

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
        return "BundID Session Email Importer";
    }

    @Override
    public String getDisplayType() {
        return "BundID Session Email Importer";
    }

    @Override
    protected void updateSession(
            KeycloakSession session, BrokeredIdentityContext context, String key, String value, boolean isStorkLevel) {
        super.updateSession(session, context, key, value, isStorkLevel);
        context.setEmail(value);
    }
}
