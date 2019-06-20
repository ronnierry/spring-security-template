package com.ry.springsecurityi.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.DefaultCsrfToken;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class ResponseHeadCsrfFilter extends OncePerRequestFilter {
    @Autowired
    HttpSessionCsrfTokenRepository httpSessionCsrfTokenRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {
        Object attribute = httpServletRequest.getSession().getAttribute("X-CSRF-TOKEN");
        if (attribute != null) {
            httpServletResponse.setHeader("X-CSRF-TOKEN", ((CsrfToken) attribute).getToken());
        }
        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }
}
