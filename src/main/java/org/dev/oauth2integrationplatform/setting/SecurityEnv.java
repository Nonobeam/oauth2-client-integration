package org.dev.oauth2integrationplatform.setting;

import lombok.Data;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Data
public class SecurityEnv {
  private Rsa rsa;

  public RSAPrivateKey getRSAPrivateKey() {
    try {
      byte[] privateKeyBytes = Base64.getDecoder().decode(this.rsa.getPrivateKey());
      PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
      return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
    } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
      throw new IllegalArgumentException("Error retrieving RSA private key", e);
    }
  }

  public RSAPublicKey getRSAPublicKey() {
    try {
      byte[] publicKeyBytes = Base64.getDecoder().decode(this.rsa.getPublicKey());
      X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
      return (RSAPublicKey) keyFactory.generatePublic(keySpec);
    } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
      throw new IllegalArgumentException("Error retrieving RSA public key", e);
    }
  }

  @Data
  private static class Rsa {
    public String publicKey;
    public String privateKey;
  }
}
