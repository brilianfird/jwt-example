package com.brilianfird.jwtexample.service.impl;

import com.brilianfird.jwtexample.model.SigningAlgorithm;
import com.brilianfird.jwtexample.service.JWTRoutingService;
import com.brilianfird.jwtexample.service.JWTService;
import lombok.RequiredArgsConstructor;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class JWTRoutingServiceImpl implements JWTRoutingService {

  private final List<JWTService> jwtServices;

  @Override
  public JsonWebSignature createJWT(
      SigningAlgorithm signingAlgorithm, String username, Map<String, Object> payload)
      throws Exception {
    return jwtServices.stream()
        .filter(jwtService -> jwtService.getSupportedAlgorithm() == signingAlgorithm)
        .findFirst()
        .map(jwtService -> jwtService.create(username, payload))
        .orElseThrow(() -> new Exception("Signing Algorithm is not supported"));
  }

  @Override
  public JwtClaims validateJWT(String jwt) throws Exception {

    JsonWebSignature jsonWebSignature = new JsonWebSignature();
    jsonWebSignature.setCompactSerialization(jwt);

    return jwtServices.stream()
        .filter(
            jwtService ->
                jwtService
                    .getSupportedAlgorithm()
                    .name()
                    .equalsIgnoreCase(jsonWebSignature.getAlgorithmHeaderValue()))
        .findFirst()
        .map(
            jwtService -> {
              try {
                return jwtService.validateJWTAndGetClaims(jwt);
              } catch (InvalidJwtException e) {
                throw new RuntimeException();
              }
            })
        .orElseThrow(() -> new Exception("Signing Algorithm is not supported"));
  }
}
