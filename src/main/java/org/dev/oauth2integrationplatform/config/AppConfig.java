package org.dev.oauth2integrationplatform.config;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.introspect.AccessorNamingStrategy;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.dev.oauth2integrationplatform.setting.CorsConfigModel;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import com.fasterxml.jackson.databind.introspect.DefaultAccessorNamingStrategy.Provider;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.util.List;
import java.util.Map;

@Configuration
public class AppConfig {
  @Bean
  ObjectMapper objectMapper() {
    ObjectMapper mapper =
            JsonMapper.builder()
                    .accessorNaming(new Provider().withBuilderPrefix(""))
                    .configure(MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES, true)
                    .configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false)
                    .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
                    .propertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE)
                    .serializationInclusion(JsonInclude.Include.NON_NULL)
                    .build();
    mapper.registerModule(new JavaTimeModule());
    return mapper;
  }

  @Bean
  MappingJackson2HttpMessageConverter jackson2HttpMessageConverter(ObjectMapper objectMapper) {
    MappingJackson2HttpMessageConverter converter = new MappingJackson2HttpMessageConverter();
    converter.setObjectMapper(objectMapper);
    return converter;
  }

  @Bean("authorizationGrantTypes")
  public Map<String, List<AuthorizationGrantType>> authorizationGrantTypeMap() {
    return Map.of(
            "google",
            List.of(AuthorizationGrantType.AUTHORIZATION_CODE, AuthorizationGrantType.REFRESH_TOKEN),
            "linkedIn",
            List.of(AuthorizationGrantType.AUTHORIZATION_CODE, AuthorizationGrantType.REFRESH_TOKEN),
            "github",
            List.of(AuthorizationGrantType.AUTHORIZATION_CODE, AuthorizationGrantType.REFRESH_TOKEN));
  }

  @Bean("corsConfig")
  @ConfigurationProperties("app.cors-config")
  public CorsConfigModel uiSetting() {
    return new CorsConfigModel();
  }
}
