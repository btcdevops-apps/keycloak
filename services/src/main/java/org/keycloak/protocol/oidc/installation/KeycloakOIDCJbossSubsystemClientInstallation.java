/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.protocol.oidc.installation;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.protocol.ClientInstallationProvider;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.services.managers.ClientManager;

import javax.ws.rs.core.MediaType;
import java.util.Map;

/**
 * Generates a Keycloak Client configuration for the Wildfly Subsystem.
 *
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class KeycloakOIDCJbossSubsystemClientInstallation extends KeycloakOIDCClientInstallation {

    @Override
    protected String generateAdapterInstallationText(ClientManager.InstallationAdapterConfig adapterConfig) {

        StringBuilder subsystemXml = new StringBuilder();

        subsystemXml.append("<secure-deployment name=\"WAR MODULE NAME.war\">\n");
        subsystemXml.append("    <realm>").append(adapterConfig.getRealm()).append("</realm>\n");
        subsystemXml.append("    <auth-server-url>").append(adapterConfig.getAuthServerUrl()).append("</auth-server-url>\n");

        if (adapterConfig.getBearerOnly() != null && adapterConfig.getBearerOnly()){
            subsystemXml.append("    <bearer-only>true</bearer-only>\n");

        } else if (adapterConfig.getPublicClient() != null && adapterConfig.getPublicClient()) {
            subsystemXml.append("    <public-client>true</public-client>\n");
        }

        subsystemXml.append("    <ssl-required>").append(adapterConfig.getSslRequired()).append("</ssl-required>\n");
        subsystemXml.append("    <resource>").append(adapterConfig.getResource()).append("</resource>\n");

        if (adapterConfig.getCredentials() != null && adapterConfig.getCredentials().isEmpty()){
            for (Map.Entry<String, Object> entry : adapterConfig.getCredentials().entrySet()) {
                subsystemXml.append("    <credential name=\"" + entry.getKey() + "\">");

                Object value = entry.getValue();
                if (value instanceof Map) {
                    subsystemXml.append("\n");
                    Map<String, Object> asMap = (Map<String, Object>) value;
                    for (Map.Entry<String, Object> credEntry : asMap.entrySet()) {
                        subsystemXml.append("        <" + credEntry.getKey() + ">" + credEntry.getValue().toString() + "</" + credEntry.getKey() + ">\n");
                    }
                    subsystemXml.append("    </credential>\n");
                } else {
                    subsystemXml.append(value.toString()).append("</credential>\n");
                }
            }
        }

        if (adapterConfig.isUseResourceRoleMappings() != null && adapterConfig.isUseResourceRoleMappings()){
            subsystemXml.append("    <use-resource-role-mappings>true</use-resource-role-mappings>\n");
        }

        subsystemXml.append("</secure-deployment>\n");

        return subsystemXml.toString();
    }

    @Override
    public String getProtocol() {
        return OIDCLoginProtocol.LOGIN_PROTOCOL;
    }

    @Override
    public String getDisplayType() {
        return "Keycloak OIDC JBoss Subsystem XML";
    }

    @Override
    public String getHelpText() {
        return "XML snippet you must edit and add to the Keycloak OIDC subsystem on your client app server.  This type of configuration is useful when you can't or don't want to crack open your WAR file.";
    }

    @Override
    public void close() {

    }

    @Override
    public ClientInstallationProvider create(KeycloakSession session) {
        return this;
    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public String getId() {
        return "keycloak-oidc-jboss-subsystem";
    }

    @Override
    public boolean isDownloadOnly() {
        return false;
    }

    @Override
    public String getFilename() {
        return "keycloak-oidc-subsystem.xml";
    }

    @Override
    public String getMediaType() {
        return MediaType.APPLICATION_XML;
    }
}

