package com.brilianfird.jwtexample.controller.handler;

import com.brilianfird.jwtexample.annotation.AuthorizationRequired;
import com.brilianfird.jwtexample.service.AuthorizationValidationService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.lang.reflect.Method;
import java.util.Objects;

@Component
@RequiredArgsConstructor
public class AuthorizationHandler implements HandlerInterceptor {

  private final AuthorizationValidationService loginValidationService;

  @Override
  public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
      throws Exception {
    AuthorizationRequired loginRequired = isLoginRequired(handler);
    if (!Objects.isNull(loginRequired)) {
      String authorization = request.getHeader("Authorization");
      if (authorization == null) {
        response.sendError(401);
        return false;
      }

      String token = authorization.split(" ")[1];
      boolean isJWTValid = loginValidationService.validateLogin(token, loginRequired.scopes());
      if (!isJWTValid) {
        response.sendError(401);
        return false;
      }
    }
    return HandlerInterceptor.super.preHandle(request, response, handler);
  }

  private AuthorizationRequired isLoginRequired(Object handler) {
    HandlerMethod handlerMethod = (HandlerMethod) handler;
    Method method = handlerMethod.getMethod();
    return method.getAnnotation(AuthorizationRequired.class);
  }
}
