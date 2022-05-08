package com.brilianfird.jwtexample.controller;

import com.brilianfird.jwtexample.model.web.JWTRequest;
import com.brilianfird.jwtexample.model.web.JWTResponse;
import com.brilianfird.jwtexample.service.JWTRoutingService;
import lombok.RequiredArgsConstructor;
import org.jose4j.jws.JsonWebSignature;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;

@RestController
@RequiredArgsConstructor
public class JWTController {

    private final JWTRoutingService jwtRoutingService;

    @PostMapping("/jwt")
    public JWTResponse createJwt(@RequestBody JWTRequest jwtRequest) throws Exception {
        HashMap<String, Object> hashmap = new HashMap<>();
        hashmap.put("scopes", jwtRequest.scopes());
        JsonWebSignature jwt = jwtRoutingService.createJWT(jwtRequest.signingAlgorithm(), jwtRequest.username(), hashmap);

        return new JWTResponse(jwt.getCompactSerialization());
    }

}
