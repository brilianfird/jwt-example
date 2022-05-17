package com.brilianfird.jwtexample.controller;

import com.brilianfird.jwtexample.annotation.AuthorizationRequired;
import com.brilianfird.jwtexample.model.web.EmployeeResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class ResourceController {

  @AuthorizationRequired(scopes = {"employee.read"})
  @GetMapping("/employee")
  public EmployeeResponse getResource() {
    return new EmployeeResponse("Brilian");
  }
}
