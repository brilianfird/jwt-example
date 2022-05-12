package com.brilianfird.jwtexample.configuration;

import com.brilianfird.jwtexample.controller.handler.AuthorizationHandler;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
@RequiredArgsConstructor
public class HandlerConfiguration implements WebMvcConfigurer {

  private final AuthorizationHandler jwtFilter;

  @Override
  public void addInterceptors(InterceptorRegistry registry) {
    registry.addInterceptor(jwtFilter);
    WebMvcConfigurer.super.addInterceptors(registry);
  }
}
