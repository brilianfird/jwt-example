package com.brilianfird.jwtexample.configuration;

import com.brilianfird.jwtexample.configuration.properties.KeyProperties;
import lombok.RequiredArgsConstructor;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.keys.HmacKey;
import org.jose4j.lang.JoseException;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Configuration
@RequiredArgsConstructor
public class KeyConfiguration {

  public static final String KEY_FACTORY_INSTANCE = "EC";
  private final KeyProperties keyProperties;

  @Bean
  public HmacKey hmacKey() {
    byte[] hmacKeyByte = Base64.getDecoder().decode(keyProperties.getBase64HmacKey());

    return new HmacKey(hmacKeyByte);
  }

  @Bean
  public PublicJsonWebKey es256PublicJsonWebKey()
      throws NoSuchAlgorithmException, JoseException, InvalidKeySpecException {
    PKCS8EncodedKeySpec formatted_private =
        new PKCS8EncodedKeySpec(
            Base64.getDecoder().decode(keyProperties.getEcdsaKey().getBase64PrivateKey()));
    X509EncodedKeySpec formatted_public =
        new X509EncodedKeySpec(
            Base64.getDecoder().decode(keyProperties.getEcdsaKey().getBase64PublicKey()));

    KeyFactory keyFactory = KeyFactory.getInstance(KEY_FACTORY_INSTANCE);
    PublicKey publicKey = keyFactory.generatePublic(formatted_public);
    PrivateKey privateKey = keyFactory.generatePrivate(formatted_private);

    PublicJsonWebKey publicJsonWebKey = PublicJsonWebKey.Factory.newPublicJwk(publicKey);
    publicJsonWebKey.setPrivateKey(privateKey);
    publicJsonWebKey.setKeyId("2022-05-08");
    return publicJsonWebKey;
  }
}
