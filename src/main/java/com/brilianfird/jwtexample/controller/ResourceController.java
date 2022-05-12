package com.brilianfird.jwtexample.controller;

import com.brilianfird.jwtexample.annotation.AuthorizationRequired;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class ResourceController {

  @AuthorizationRequired(scopes = {"resource.read"})
  @GetMapping("/resource")
  public String getResource() {
    return "this is a resource";
  }
}
