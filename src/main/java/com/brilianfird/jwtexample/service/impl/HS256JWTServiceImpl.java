package com.brilianfird.jwtexample.service.impl;

import com.brilianfird.jwtexample.model.SigningAlgorithm;
import com.brilianfird.jwtexample.service.JWTService;
import lombok.RequiredArgsConstructor;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.keys.HmacKey;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
@RequiredArgsConstructor
public class HS256JWTServiceImpl implements JWTService {

  private final HmacKey hmacKey;
  private final JwtConsumer hmacJWTConsumer;

  @Override
  public JsonWebSignature create(String username, Map<String, Object> payload) {
    JsonWebSignature jsonWebSignature = new JsonWebSignature();

    JwtClaims jwtClaims = new JwtClaims();
    payload.forEach(jwtClaims::setClaim);
    jwtClaims.setIssuedAtToNow();
    jwtClaims.setIssuer("https://codecurated.com");
    jwtClaims.setExpirationTimeMinutesInTheFuture(60);
    jwtClaims.setSubject(username);

    jsonWebSignature.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA256);
    jsonWebSignature.setKey(hmacKey);
    jsonWebSignature.setPayload(jwtClaims.toJson());

    return jsonWebSignature;
  }

  @Override
  public JwtClaims validateJWTAndGetClaims(String jwt) throws InvalidJwtException {
    JwtClaims jwtClaims = hmacJWTConsumer.processToClaims(jwt);
    return jwtClaims;
  }

  @Override
  public SigningAlgorithm getSupportedAlgorithm() {
    return SigningAlgorithm.HS256;
  }
}
