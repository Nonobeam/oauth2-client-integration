package org.dev.oauth2integrationplatform.domain;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table(name = "oauth2_client_config")
public class Oauth2ClientConfig {
  @Id
  @GeneratedValue(strategy = GenerationType.UUID)
  private String id;

  private String provider;

  private String clientId;

  private String clientSecret;

  private String redirectUri;

  private String scope;

  private String redirectUrls;

  private String authorizeUrls;

  private String tokenUrl;

  private String userInfoUrl;

  private String grantTypes;

  private String enabled;

  private Long createdAt;

  private Long updatedAt;
}