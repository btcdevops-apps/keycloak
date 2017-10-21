package org.keycloak.procotol.oidc.installation;

import org.junit.Before;
import org.junit.Test;
import org.keycloak.protocol.oidc.installation.KeycloakOIDCSpringBootPropertiesInstallation;
import org.keycloak.services.managers.ClientManager.InstallationAdapterConfig;

import java.util.Collections;

public class KeycloakOIDCSpringBootPropertiesInstallationTest {

  KeycloakOIDCSpringBootPropertiesInstallation provider;

  @Before
  public void setup(){
    provider = new KeycloakOIDCSpringBootPropertiesInstallation();
  }

  private InstallationAdapterConfig newClientConfig() {

    //TODO generate more client variants...

    InstallationAdapterConfig clientConfig = new InstallationAdapterConfig();
    clientConfig.setResource("test-client");
    clientConfig.setAuthServerUrl("http://auth-server");
    clientConfig.setSslRequired("external");

    return clientConfig;
  }

  @Test
  public void renderConfidentialClientCorrectly() {

    InstallationAdapterConfig config = newClientConfig();
    addCredentials(config);
    addRoles(config);

    // TODO generate config via the provider ...
    // either by mocking Keycloak infrastructure or writing a full integration test...
  }

  private void addRoles(InstallationAdapterConfig config) {
    config.setUseResourceRoleMappings(true);
  }

  private void addCredentials(InstallationAdapterConfig config) {
    config.setCredentials(Collections.singletonMap("secret", "11111-111111-11111-11111"));
  }

}
