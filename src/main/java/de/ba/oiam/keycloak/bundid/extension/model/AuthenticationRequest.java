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

package de.ba.oiam.keycloak.bundid.extension.model;

import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.Marshaller;
import jakarta.xml.bind.Unmarshaller;
import jakarta.xml.bind.annotation.*;
import java.util.ArrayList;
import java.util.List;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.keycloak.dom.saml.v2.protocol.AuthnRequestType;
import org.keycloak.dom.saml.v2.protocol.ExtensionsType;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

@XmlRootElement(name = "AuthenticationRequest", namespace = "https://www.akdb.de/request/2018/09")
@XmlAccessorType(XmlAccessType.FIELD)
public class AuthenticationRequest {
    private static final JAXBContext JAXB_CONTEXT;

    static {
        try {
            JAXB_CONTEXT = JAXBContext.newInstance(AuthenticationRequest.class);
        } catch (JAXBException e) {
            throw new RuntimeException(e);
        }
    }

    @XmlAttribute(name = "Version")
    private String version = "2";

    @XmlElement(name = "AuthnMethods", namespace = "https://www.akdb.de/request/2018/09")
    private AuthnMethods authnMethods;

    @XmlElement(name = "RequestedAttributes", namespace = "https://www.akdb.de/request/2018/09")
    private RequestedAttributes requestedAttributes = new RequestedAttributes();

    @XmlElement(name = "DisplayInformation", namespace = "https://www.akdb.de/request/2018/09")
    private DisplayInformation displayInformation = new DisplayInformation();

    // getters and setters

    public AuthnMethods getAuthnMethods() {
        return authnMethods;
    }

    public void setAuthnMethods(AuthnMethods authnMethods) {
        this.authnMethods = authnMethods;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public RequestedAttributes getRequestedAttributes() {
        return requestedAttributes;
    }

    public void setRequestedAttributes(RequestedAttributes requestedAttributes) {
        this.requestedAttributes = requestedAttributes;
    }

    public DisplayInformation getDisplayInformation() {
        return displayInformation;
    }

    public void setDisplayInformation(DisplayInformation displayInformation) {
        this.displayInformation = displayInformation;
    }

    public static AuthenticationRequest readExisting(AuthnRequestType authnRequest) {
        try {
            if (authnRequest.getExtensions() == null) {
                return null;
            }

            Unmarshaller unmarshaller = JAXB_CONTEXT.createUnmarshaller();

            return authnRequest.getExtensions().getAny().stream()
                    .filter(ext -> Node.class.isAssignableFrom(ext.getClass()))
                    .map(Node.class::cast)
                    .filter(node -> node.getLocalName().equals("AuthenticationRequest"))
                    .map(node -> unmarshallUnchecked(unmarshaller, node))
                    .findFirst()
                    .orElse(null);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void addOrUpdate(AuthnRequestType authnRequest) {
        try {
            if (authnRequest.getExtensions() == null) {
                authnRequest.setExtensions(new ExtensionsType());
            }

            Marshaller marshaller = JAXB_CONTEXT.createMarshaller();
            DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
            DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
            Document document = documentBuilder.newDocument();
            marshaller.marshal(this, document);

            List<Object> allExtensions =
                    new ArrayList<>(authnRequest.getExtensions().getAny());
            allExtensions.forEach(ext -> authnRequest.getExtensions().removeExtension(ext));
            authnRequest.getExtensions().addExtension(document.getDocumentElement());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static AuthenticationRequest unmarshallUnchecked(Unmarshaller unmarshaller, Node node) {
        try {
            return (AuthenticationRequest) unmarshaller.unmarshal(node);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
