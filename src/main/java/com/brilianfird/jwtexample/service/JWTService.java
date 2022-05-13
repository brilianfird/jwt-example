package com.brilianfird.jwtexample.service;

import com.brilianfird.jwtexample.model.SigningAlgorithm;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;

import java.util.Map;

public interface JWTService {
  JsonWebSignature create(String username, Map<String, Object> payload);

  JwtClaims validateJWTAndGetClaims(String jwt) throws InvalidJwtException;

  SigningAlgorithm getSupportedAlgorithm();
}
