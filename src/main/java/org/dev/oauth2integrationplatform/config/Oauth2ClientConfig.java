package org.dev.oauth2integrationplatform.config;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.web.cors.CorsConfigurationSource;

@Configuration
public class Oauth2ClientConfig {
  private static final String[] AUTHENTICATION_ENDPOINT = {
          "/", "/oauth2/authorization/*", "/login/oauth2/callback/*"
  };

  @Bean
  @Order(1)
  SecurityFilterChain requestSecurityFilterChain(
          HttpSecurity http,
          @Qualifier("corsConfigurationSource") CorsConfigurationSource corsConfigurationSource,
          @Qualifier("authenticationSuccessHandlerCustomize") AuthenticationSuccessHandler authenticationSuccessHandler)
          throws Exception {

    http.securityMatcher(AUTHENTICATION_ENDPOINT)
            .cors(cors -> cors.configurationSource(corsConfigurationSource))
            .authorizeHttpRequests(requests -> requests.anyRequest().authenticated())
            .sessionManagement(
                    session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .oauth2Login(
                    login ->
                            login
                                    .redirectionEndpoint(endpoint -> endpoint.baseUri("/login/oauth2/callback/*"))
                                    .successHandler(authenticationSuccessHandler));
    return http.build();
  }
}