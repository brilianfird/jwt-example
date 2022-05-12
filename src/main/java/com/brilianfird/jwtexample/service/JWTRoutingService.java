package com.brilianfird.jwtexample.service;

import com.brilianfird.jwtexample.model.SigningAlgorithm;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;

import java.util.Map;

public interface JWTRoutingService {
  JsonWebSignature createJWT(
      SigningAlgorithm signingAlgorithm, String username, Map<String, Object> payload)
      throws Exception;

  JwtClaims validateJWT(String jwt) throws Exception;
}
