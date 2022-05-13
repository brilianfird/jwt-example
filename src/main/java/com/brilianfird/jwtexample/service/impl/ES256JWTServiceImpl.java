package com.brilianfird.jwtexample.service.impl;

import com.brilianfird.jwtexample.model.SigningAlgorithm;
import com.brilianfird.jwtexample.service.JWTService;
import lombok.RequiredArgsConstructor;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
@RequiredArgsConstructor
public class ES256JWTServiceImpl implements JWTService {

  private final PublicJsonWebKey es256PublicJsonWebKey;
  private final JwtConsumer es256JWTConsumer;

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
    jsonWebSignature.setKeyIdHeaderValue(es256PublicJsonWebKey.getKeyId());

    return jsonWebSignature;
  }

  @Override
  public JwtClaims validateJWTAndGetClaims(String jwt) throws InvalidJwtException {
    return es256JWTConsumer.processToClaims(jwt);
  }

  @Override
  public SigningAlgorithm getSupportedAlgorithm() {
    return SigningAlgorithm.ES256;
  }
}
