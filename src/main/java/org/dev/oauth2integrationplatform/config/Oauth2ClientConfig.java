package org.dev.oauth2integrationplatform.config;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.dev.oauth2integrationplatform.security.JwtAuthenticationFilter;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Arrays;

@Slf4j
@EnableWebSecurity(debug = true)
@Configuration
@RequiredArgsConstructor
public class Oauth2ClientConfig {

  private final JwtDecoder jwtDecoder;
  private final ClientRegistrationRepository clientRegistrationRepository;

  private final String[] ALLOW_ENDPOINTS = {
          "/v2/api-docs/**",
          "/v3/api-docs",
          "/v3/**",
          "/swagger-ui/**",
          "/swagger-ui.html",
          "/swagger-resources",
          "/swagger-resources/**",
          "/swagger-ui/index.html#/**",
          "/actuator/**",
          "/favicon.ico",
          "/login",
          "/index.html",
          "/assets/**",
          "/vite.svg",
          "/api/auth/**",
          "/api/users/activate/**",
          "/api/transactions/webhook",
          "/api/auth/login",
          "/error"
  };

  private final String[] POST_ENDPOINTS = {};

  private final String[] GET_ENDPOINTS = {};

  @Bean
  @Order(1)
  public SecurityFilterChain publicFilterChain(
          HttpSecurity http,
          @Qualifier("corsConfigurationSource") CorsConfigurationSource corsConfigurationSource
  ) throws Exception {
    http.securityMatcher(this::isAllowEndpoint)
            .cors(cors -> cors.configurationSource(corsConfigurationSource))
            .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .csrf(AbstractHttpConfigurer::disable);

    return http.build();
  }

  @Bean
  @Order(2)
  public SecurityFilterChain securedFilterChain(
          HttpSecurity http,
          @Qualifier("corsConfigurationSource") CorsConfigurationSource corsConfigurationSource,
          @Qualifier("authenticationSuccessHandlerCustomize") AuthenticationSuccessHandler authenticationSuccessHandler)
          throws Exception {
    http.csrf(AbstractHttpConfigurer::disable)
            .cors(cors -> cors.configurationSource(corsConfigurationSource))
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
            .addFilterBefore(
                    new JwtAuthenticationFilter(jwtDecoder), UsernamePasswordAuthenticationFilter.class)
            .oauth2Login(
                    oauth ->
                            oauth
                                    .authorizationEndpoint(
                                            authorizationEndpoint ->
                                                    authorizationEndpoint.authorizationRequestResolver(
                                                            authorizationRequestResolver()))
                                    .successHandler(authenticationSuccessHandler));

    return http.build();
  }

  private OAuth2AuthorizationRequestResolver authorizationRequestResolver() {

    DefaultOAuth2AuthorizationRequestResolver resolver =
            new DefaultOAuth2AuthorizationRequestResolver(
                    clientRegistrationRepository, "/oauth2/authorization");
    resolver.setAuthorizationRequestCustomizer(
            customizer ->
                    customizer
                            .attributes(a -> a.remove(OidcParameterNames.NONCE))
                            .parameters(p -> p.remove(OidcParameterNames.NONCE)));

    return resolver;
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  public AuthenticationManager authenticationManager(AuthenticationConfiguration config)
          throws Exception {
    return config.getAuthenticationManager();
  }

  @Bean
  public AuthenticationEventPublisher authenticationEventPublisher() {
    return new AuthenticationEventPublisher() {
      @Override
      public void publishAuthenticationSuccess(Authentication authentication) {
        log.info("Authentication success for: {}", authentication.getPrincipal());
      }

      @Override
      public void publishAuthenticationFailure(
              AuthenticationException exception, Authentication authentication) {
        log.error("Authentication failure: {}", exception.getMessage(), exception);
      }
    };
  }

  private boolean isAllowEndpoint(HttpServletRequest request) {
    String method = request.getMethod();
    String path = request.getServletPath();

    boolean isAllowed = Arrays.asList(ALLOW_ENDPOINTS).contains(path);
    boolean isGetAllowed =
            HttpMethod.GET.matches(method) && Arrays.stream(GET_ENDPOINTS).anyMatch(path::matches);
    boolean isPostAllowed =
            HttpMethod.POST.matches(method) && Arrays.stream(POST_ENDPOINTS).anyMatch(path::matches);

    return isAllowed || isGetAllowed || isPostAllowed;
  }
}