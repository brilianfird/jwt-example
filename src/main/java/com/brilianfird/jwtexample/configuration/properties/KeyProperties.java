package com.brilianfird.jwtexample.configuration.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "key")
@Data
public class KeyProperties {
  private String base64HmacKey;
  private RSA ecdsaKey;

  @Data
  public static class RSA {
    private String base64PrivateKey;
    private String base64PublicKey;
  }
}
