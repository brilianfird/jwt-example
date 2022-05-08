package com.brilianfird.jwtexample.controller;

import com.brilianfird.jwtexample.service.JWTRoutingService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class ResourceController {
    private final JWTRoutingService jwtRoutingService;

    @GetMapping("/resource")
    public Boolean getResource(@RequestHeader("Authorization") String authorization) {
        try {
            return jwtRoutingService.validateJWT(authorization);
        } catch (Exception e) {
            return false;
        }
    }
}
