package com.brilianfird.jwtexample.service;

import com.brilianfird.jwtexample.model.SigningAlgorithm;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.lang.JoseException;

import java.util.Map;

public interface JWTService {
    JsonWebSignature create(String username, Map<String, Object> payload);

    Boolean validate(String jwt) throws JoseException;

    SigningAlgorithm getSupportedAlgorithm();
}
