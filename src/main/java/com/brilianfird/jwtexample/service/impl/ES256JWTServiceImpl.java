package com.brilianfird.jwtexample.service.impl;

import com.brilianfird.jwtexample.model.SigningAlgorithm;
import com.brilianfird.jwtexample.service.JWTService;
import lombok.RequiredArgsConstructor;
import org.jose4j.jwk.HttpsJwks;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.resolvers.HttpsJwksVerificationKeyResolver;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
@RequiredArgsConstructor
public class ES256JWTServiceImpl implements JWTService {

  private final PublicJsonWebKey es256PublicJsonWebKey;

  @Override
  public JsonWebSignature create(String username, Map<String, Object> payload) {
    JsonWebSignature jsonWebSignature = new JsonWebSignature();

    JwtClaims jwtClaims = new JwtClaims();
    payload.forEach(jwtClaims::setClaim);
    jwtClaims.setIssuedAtToNow();
    jwtClaims.setIssuer("https://codecurated.com");
    jwtClaims.setExpirationTimeMinutesInTheFuture(60);
    jwtClaims.setSubject(username);

    jsonWebSignature.setAlgorithmHeaderValue(
        AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
    jsonWebSignature.setKey(es256PublicJsonWebKey.getPrivateKey());
    jsonWebSignature.setPayload(jwtClaims.toJson());

    return jsonWebSignature;
  }

  @Override
  public JwtClaims validate(String jwt) throws InvalidJwtException {

    JwtConsumer jwtConsumer =
        new JwtConsumerBuilder()
            .setSkipDefaultAudienceValidation()
            .setVerificationKeyResolver(
                new HttpsJwksVerificationKeyResolver(new HttpsJwks("http://localhost:8080/jwk")))
            .build();
    jwtConsumer.processToClaims(jwt);
    return jwtConsumer.processToClaims(jwt);
  }

  @Override
  public SigningAlgorithm getSupportedAlgorithm() {
    return SigningAlgorithm.ES256;
  }
}
