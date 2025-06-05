package org.dev.oauth2integrationplatform.security;

import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

import java.util.List;

@Configuration
public class OAuth2LoginConfig {

  @Bean
  public ClientRegistrationRepository clientRegistrationRepository(
      OAuth2ClientProperties properties) {
    List<ClientRegistration> registrations =
        properties.getRegistration().keySet().stream()
            .map(client -> getRegistration(properties, client))
            .toList();
    return new InMemoryClientRegistrationRepository(registrations);
  }

  private ClientRegistration getRegistration(OAuth2ClientProperties properties, String client) {
    OAuth2ClientProperties.Registration registration = properties.getRegistration().get(client);
    OAuth2ClientProperties.Provider provider =
        properties.getProvider().get(registration.getProvider());

    return ClientRegistration.withRegistrationId(client)
        .clientId(registration.getClientId())
        .clientSecret(registration.getClientSecret())
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri(registration.getRedirectUri())
        .scope(registration.getScope())
        .authorizationUri(provider.getAuthorizationUri())
        .tokenUri(provider.getTokenUri())
        .userInfoUri(provider.getUserInfoUri())
        .userNameAttributeName(provider.getUserNameAttribute())
        .jwkSetUri(provider.getJwkSetUri())
        .issuerUri(provider.getIssuerUri())
        .clientName(registration.getClientName())
        .build();
  }
}
