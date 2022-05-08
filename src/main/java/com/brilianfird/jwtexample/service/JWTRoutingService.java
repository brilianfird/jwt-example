package com.brilianfird.jwtexample.service;

import com.brilianfird.jwtexample.model.SigningAlgorithm;
import org.jose4j.jws.JsonWebSignature;

import java.util.Map;

public interface JWTRoutingService {
    JsonWebSignature createJWT(SigningAlgorithm signingAlgorithm, String username, Map<String, Object> payload) throws Exception;

    Boolean validateJWT(String jwt) throws Exception;
}
