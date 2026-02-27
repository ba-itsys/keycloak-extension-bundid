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

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElement;

@XmlAccessorType(XmlAccessType.FIELD)
public class AuthnMethods {

    @XmlElement(name = "Authega", namespace = "https://www.akdb.de/request/2018/09")
    private AuthnMethodEnabled authega;

    @XmlElement(name = "Benutzername", namespace = "https://www.akdb.de/request/2018/09")
    private AuthnMethodEnabled benutzername;

    @XmlElement(name = "Diia", namespace = "https://www.akdb.de/request/2018/09")
    private AuthnMethodEnabled diia;

    @XmlElement(name = "eID", namespace = "https://www.akdb.de/request/2018/09")
    private AuthnMethodEnabled eid;

    @XmlElement(name = "eIDAS", namespace = "https://www.akdb.de/request/2018/09")
    private AuthnMethodEnabled eidas;

    @XmlElement(name = "Elster", namespace = "https://www.akdb.de/request/2018/09")
    private AuthnMethodEnabled elster;

    @XmlElement(name = "FINK", namespace = "https://www.akdb.de/request/2018/09")
    private AuthnMethodEnabled fink;

    public AuthnMethodEnabled getAuthega() {
        return authega;
    }

    public void setAuthega(AuthnMethodEnabled authega) {
        this.authega = authega;
    }

    public AuthnMethodEnabled getDiia() {
        return diia;
    }

    public void setDiia(AuthnMethodEnabled diia) {
        this.diia = diia;
    }

    public AuthnMethodEnabled getEid() {
        return eid;
    }

    public void setEid(AuthnMethodEnabled eid) {
        this.eid = eid;
    }

    public AuthnMethodEnabled getEidas() {
        return eidas;
    }

    public void setEidas(AuthnMethodEnabled eidas) {
        this.eidas = eidas;
    }

    public AuthnMethodEnabled getElster() {
        return elster;
    }

    public void setElster(AuthnMethodEnabled elster) {
        this.elster = elster;
    }

    public AuthnMethodEnabled getFink() {
        return fink;
    }

    public void setFink(AuthnMethodEnabled fink) {
        this.fink = fink;
    }

    public AuthnMethodEnabled getBenutzername() {
        return benutzername;
    }

    public void setBenutzername(AuthnMethodEnabled benutzername) {
        this.benutzername = benutzername;
    }
}
