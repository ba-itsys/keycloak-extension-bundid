[![CI](httpseasily://github.com/opdt/keycloak-extension-bundid/workflows/CI/badge.svg)](https://github.com/opdt/keycloak-extension-bundid/actions?query=workflow%3ACI)
[![Maven Central](https://img.shields.io/maven-central/v/de.arbeitsagentur.opdt/keycloak-extension-bundid.svg)](https://search.maven.org/artifact/de.arbeitsagentur.opdt/keycloak-extension-bundid)

# keycloak-extension-bundid

This extension makes it possible to use BundID as an identity provider in Keycloak.
It handles the technical details of the SAML communication with BundID, so you don't have to implement this yourself.
By using this extension, you can connect your applications to BundID and authenticate users with their BundID accounts.

Specifically, this extension provides:
*   **BundID SAML Integration:** Facilitates SAML-based identification with BundID by automatically enriching SAML requests with necessary trust levels and user information.
*   **Attribute Mapping:** Provides mappers to transfer BundID user attributes (like email, retrieval timestamp) into Keycloak sessions and OIDC tokens.
*   **Configurable Trust Levels:** Enables configuration of minimum required trust levels (Level of Authentication - LoA) for authentication with BundID.
*   **Mandatory Fields:** Supports the transmission of future mandatory BundID attributes (e.g., Organization Display Name, Online Service ID).

⚠️ The following docs are in german due to the intended audience of mainly german authorities, who need/want to integrate BundID into their own Keycloak installation.
Feel free to reach out if you need to integrate BundID as a non german speaking entity and need help doing so.


## Einleitung

Die Nutzung von *BundID* für die Identifizierung basiert auf *SAML*. Im *SAML-Request* müssen einige Einstellungen für das benötigte Vertrausniveau, die zulesenden Elemente 
und *DisplayInformation* abgebildet sein. Diese *Keycloak-Extension* sorgt für die Anreicherung des *SAML-Requests*.

## Installation & Einbindung

Die Extension kann von Maven Central bezogen und in das `providers`-Verzeichnis von Keycloak kopiert werden.
Der Kernbestandteil ist eine Implementierung des `AuthenticationPreprocessor`-Interfaces, welches die Anreicherung des SAML-Requests übernimmt.
Zur Steuerung, für welchen Identity Provider die Anbindung erfolgen soll, muss die Konfigurationsoption `KC_SPI_SAML_AUTHENTICATION_PREPROCESSOR_BUNDID_PROTOCOL_ACTIVE_FOR_IDP` gesetzt werden.
Der Default-Wert ist `bundid`. D.h. wenn dieser Name für den BundID-Identity Provider verwendet wird, funktioniert die Anbindung ohne gesonderte Konfiguration.

## Konfiguration

Die Extension definiert mehrere IdentityProviderMapper:

- `saml-bundid-session-attribute-idp-mapper` (für das Mapping von BundID-Attributen in die Keycloak-Session)
- `saml-bundid-session-email-idp-mapper` (setzt zusätzlich die E-Mail im BrokeredIdentityContext und macht sie damit für die weitere Verarbeitung in Keycloak bekannt)
- `saml-retrieval-time-session-attribute-idp-mapper` (für das Mapping des Zeitstempels der BundID-Authentifizierung in die Keycloak-Session)

Außerdem wird ein ProtocolMapper definiert:
- `oidc-bundid-sessionnote-mapper` (zum Mapping der Attribute aus der UserSession in das Token)

Die Funktionsweise ist dabei, dass über den `saml-bundid-session-attribute-idp-mapper` die jeweiligen BundID-Attribute (+ das jeweilige Vertrauensniveau) in die Keycloak-Session gemappt werden.
Zusätzlich werden dort, über die angegebene `OID`, die Attribute im SAML-Request angefordert.

Über den `oidc-bundid-sessionnote-mapper` werden alle BundID-Attribute aus der Session in das Token gemappt.
Diese werden über einen Namenspräfix `ba.bundid_prop_` ausgezeichnet und im ProtocolMapper erkannt. 
Es ist über die Parameter der Mapper möglich, einzelne Attribute vom Automapping auszuschließen.

## Funktionsweise
### Deklaration der angeforderten Attribute

    <saml2p:Extensions>
        <akdb:AuthenticationRequest xmlns:akdb="https://www.akdb.de/request/2018/09" Version="2">
            <akdb:RequestedAttributes>
                <akdb:RequestedAttribute Name="urn:oid:2.5.4.18" RequiredAttribute="false" />
                <akdb:RequestedAttribute Name="urn:oid:1.2.40.0.10.2.1.1.149" RequiredAttribute="true" />
                <akdb:RequestedAttribute Name="urn:oid:1.3.6.1.4.1.25484.494450.3"/>
                ...
            </akdb:RequestedAttributes>
        </akdb:AuthenticationRequest>
    </saml2p:Extensions>

Diese Extension definiert einen eigenen IdentityProviderMapper (für das Mapping von BundID-Attributen in die Keycloak-Session): `saml-bundid-session-attribute-idp-mapper`.
Dieser Mapper erlaubt zusätzlich die Angabe einer `OID` sowie ob das Feld als Pflichtattribut angefordert werden soll. 
Dadurch werden automatisch die o.g. `RequestedAttributes` im SAML-Request befüllt.

Zur weiteren Vereinfachung gibt es zudem die Möglichkeit, den `oidc-bundid-sessionnote-mapper` (Keycloak-ProtocolMapper zum Mapping der Attribute aus der UserSession in das Token) zu nutzen.
Darüber werden alle vom `saml-bundid-session-attribute-idp-mapper` in die Session gemappten Attribute (+ jeweils ein Attribut zur Angabe des zugehörigen Vertrauensniveaus) in das Token gemapped.
	
### Anforderung minimales Vertrauensniveau

	<saml2p:RequestedAuthnContext Comparison="minimum">
		<saml2:AuthnContextClassRef xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">STORK-QAA-Level-3</saml2:AuthnContextClassRef>
	</saml2p:RequestedAuthnContext>

Gesteuert wird dies über das angeforderte `Level of Authentication (LoA)`, wobei hier die Werte 1 bis 4 zulässig sind.
Die Anforderung von LoA erfolgt über die Keycloak Step-Up-Authentication. Weitere Infos sind der Keycloak-Dokumentation zu entnehmen.

Zusätzlich ist es möglich, konfigurativ ein absolut minimales vertrauensniveau zu setzen. D.h. selbst wenn Keycloak ein niedrigeres LoA fordert, wird dann dieses Niveau an BundID übergeben.
Gesteuert wird dies über den Parameter `KC_SPI_SAML_AUTHENTICATION_PREPROCESSOR_BUNDID_PROTOCOL_MINIMUM_STORK_LEVEL`. 

### Übergabe weiterer Pflichtattribute

	<saml2p:Extensions>
		<akdb:AuthenticationRequest xmlns:akdb="https://www.akdb.de/request/2018/09" Version="2">
            <akdb:DisplayInformation>
                <classic-ui:Version xmlns:classic-ui="https://www.akdb.de/request/2018/09/classic-ui/v1">
                    <classic-ui:OrganizationDisplayName>Bundesagentur für Arbeit</classic-ui:OrganizationDisplayName>
                    <classic-ui:OnlineServiceId>BMI-4711</classic-ui:OnlineServiceId>
                </classic-ui:Version>
            </akdb:DisplayInformation>
		</akdb:AuthenticationRequest>
	</saml2p:Extensions>

Die BundID schreibt zukünftig die Übergabe weiterer Pflichtattribute vor:
- Organization Display Name (wird dem Nutzer vor Rücksprung zum Service Provider angezeigt)
- Online Service ID (der für den Service Provider durch das BSI vergebene Identifier)

Die Werte für diese Attribute werden über Keycloak-Konfigurationsparameter definiert (hier als ENV-Variable angegeben, kann aber analog sonstiger Keycloak-Konfiguration auch anders gesetzt werden):
- `KC_SPI_SAML_AUTHENTICATION_PREPROCESSOR_BUNDID_PROTOCOL_ONLINE_SERVICE_ID`
- `KC_SPI_SAML_AUTHENTICATION_PREPROCESSOR_BUNDID_PROTOCOL_ORGANIZATION_DISPLAY_NAME`
