/*
 * Copyright 2017 Red Hat, Inc. and/or its affiliates
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

import org.keycloak.services.managers.ClientManager.InstallationAdapterConfig;

import javax.ws.rs.core.MediaType;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Map;

/**
 * Generates a Keycloak Client configuration for Spring Boot in Properties format.
 *
 * @author <a href="mailto:thomas.darimont@gmail.com">Thomas Darimont</a>
 */
public class KeycloakOIDCSpringBootPropertiesInstallation extends KeycloakOIDCClientInstallation{

    @Override
    protected String generateAdapterInstallationText(InstallationAdapterConfig adapterConfig) {

        StringWriter out = new StringWriter();
        try (PrintWriter pw = new PrintWriter(out)) {
            pw.printf("keycloak.realm=%s%n", adapterConfig.getRealm());
            pw.printf("keycloak.auth-server-url=%s%n", adapterConfig.getAuthServerUrl());
            pw.printf("keycloak.resource=%s%n", adapterConfig.getResource());

            if (adapterConfig.getBearerOnly() != null && adapterConfig.getBearerOnly()) {
              pw.printf("keycloak.bearer-only=%s%n", adapterConfig.getBearerOnly());
            } else if (adapterConfig.getPublicClient() != null && adapterConfig.getPublicClient()) {
              pw.printf("keycloak.public-client=%s%n", adapterConfig.getPublicClient());
            }

            if (adapterConfig.getCredentials() != null && !adapterConfig.getCredentials().isEmpty()) {
              for (Map.Entry<String,Object> entry : adapterConfig.getCredentials().entrySet()){
                pw.printf("keycloak.credentials.%s=%s%n", entry.getKey(), entry.getValue());
              }
            }

            pw.printf("keycloak.ssl-required=%s%n", adapterConfig.getSslRequired());
            pw.printf("keycloak.principal-attribute=%s%n", "preferred_username");
            pw.printf("keycloak.use-resource-role-mappings=%s%n", adapterConfig.isUseResourceRoleMappings() != null && adapterConfig.isUseResourceRoleMappings());
        }

        return out.toString();
    }

    @Override
    public String getDisplayType() {
        return "Keycloak Spring Boot properties";
    }

    @Override
    public String getHelpText() {
        return "application.properties file used by the Spring Boot Keycloak adapter to configure clients.  This must be saved to a application.properties file and put in your resources directory of your project.  You may also want to tweak this file after you download it.";
    }

    @Override
    public String getId() {
        return "keycloak-oidc-springboot-properties";
    }

    @Override
    public boolean isDownloadOnly() {
        return false;
    }

    @Override
    public String getFilename() {
        return "application.properties";
    }

    @Override
    public String getMediaType() {
        return MediaType.TEXT_PLAIN;
    }
}
