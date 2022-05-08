package com.brilianfird.jwtexample.model.web;

import com.brilianfird.jwtexample.model.SigningAlgorithm;

import java.util.List;

public record JWTRequest(SigningAlgorithm signingAlgorithm, String username, List<String> scopes) {
}
