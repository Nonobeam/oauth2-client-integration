package org.dev.oauth2integrationplatform.domain;

import jakarta.persistence.Column;
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
@Table(name = "authentication_provider")
public class AuthenticationProvider {
  @Id
  @GeneratedValue(strategy = GenerationType.UUID)
  private String id;

  private String userId;

  private String provider;

  private String providerId;

  private String email;

  private String username;

  private String password;

  private String salt;

  @Column(name = "created_at", updatable = false)
  private Long createdAt;

  private Long updatedAt;
}