package com.brilianfird.jwtexample.controller;

import lombok.RequiredArgsConstructor;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.PublicJsonWebKey;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class JWKController {
  private final PublicJsonWebKey ecdsaPublicJsonWebKey;

  @GetMapping("/jwk")
  public String jwk() {
    JsonWebKeySet jsonWebKeySet = new JsonWebKeySet();
    jsonWebKeySet.addJsonWebKey(ecdsaPublicJsonWebKey);

    return jsonWebKeySet.toJson(JsonWebKey.OutputControlLevel.INCLUDE_SYMMETRIC);
  }
}
