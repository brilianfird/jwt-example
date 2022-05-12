package com.brilianfird.jwtexample.service;

public interface AuthorizationValidationService {
  boolean validateLogin(String jwt, String[] scopes) throws Exception;
}
