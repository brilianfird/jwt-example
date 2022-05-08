package com.brilianfird.jwtexample.service.impl;

import com.brilianfird.jwtexample.model.SigningAlgorithm;
import com.brilianfird.jwtexample.service.JWTService;
import lombok.RequiredArgsConstructor;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.keys.HmacKey;
import org.jose4j.lang.JoseException;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
@RequiredArgsConstructor
public class HS256JWTService implements JWTService {

    private final HmacKey hmacKey;

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
    public Boolean validate(String jwt) throws JoseException {
        JsonWebSignature jsonWebSignature = new JsonWebSignature();
        jsonWebSignature.setCompactSerialization(jwt);

        jsonWebSignature.setKey(hmacKey);
        return jsonWebSignature.verifySignature();
    }

    @Override
    public SigningAlgorithm getSupportedAlgorithm() {
        return SigningAlgorithm.HS256;
    }
}
