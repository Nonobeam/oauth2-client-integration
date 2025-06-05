package org.dev.oauth2integrationplatform.security;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import lombok.RequiredArgsConstructor;
import org.dev.oauth2integrationplatform.setting.SecurityEnv;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

@Configuration
@RequiredArgsConstructor
public class JwtConfig {
  private final SecurityEnv securityEnv;

  @Bean
  public JwtEncoder jwtEncoder() {
    var publicKey = securityEnv.getRSAPublicKey();
    var privateKey = securityEnv.getRSAPrivateKey();
    var jwk = new RSAKey.Builder(publicKey).privateKey(privateKey).build();
    var jwkSource = new ImmutableJWKSet<>(new JWKSet(jwk));
    return new NimbusJwtEncoder(jwkSource);
  }

  @Bean
  public JwtDecoder jwtDecoder() {
    return NimbusJwtDecoder.withPublicKey(securityEnv.getRSAPublicKey()).build();
  }
}
