package com.brilianfird.jwtexample.service.impl;

import com.brilianfird.jwtexample.model.exception.AuthorizationException;
import com.brilianfird.jwtexample.service.AuthorizationValidationService;
import com.brilianfird.jwtexample.service.JWTRoutingService;
import lombok.RequiredArgsConstructor;
import org.jose4j.jwt.JwtClaims;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class AuthorizationValidationServiceImpl implements AuthorizationValidationService {

  private final JWTRoutingService jwtRoutingService;

  @Override
  public boolean validateLogin(String jwt, String[] scopes) throws Exception {
    JwtClaims jwtClaims = jwtRoutingService.validateJWT(jwt);

    List<String> jwtScopes = jwtClaims.getStringListClaimValue("scopes");

    Map<String, Boolean> jwtScopeMap = new HashMap<>();
    jwtScopes.forEach(s -> jwtScopeMap.put(s, Boolean.TRUE));

    for (String scope : scopes) {
      if (!jwtScopeMap.getOrDefault(scope, Boolean.FALSE)) {
        throw new AuthorizationException();
      }
    }
    return true;
  }
}
