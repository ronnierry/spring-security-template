package com.ry.springsecurityi.config;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Arrays;
import java.util.List;

public class CustomizedAuthenticationProcessingFilter extends AbstractAuthenticationProcessingFilter {
    PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    public CustomizedAuthenticationProcessingFilter() {
        super(new AntPathRequestMatcher("/ajax-login", "POST"));
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        ProviderManager providerManager = new ProviderManager(Arrays.asList(daoAuthenticationProvider));
        this.setAuthenticationManager(providerManager);

    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws AuthenticationException {
        String username = httpServletRequest.getParameter("username");
        String password = httpServletRequest.getParameter("password");
        if (!"admin".equals(username)) {
            throw new BadCredentialsException("用户名不存在！");
        }
        if (!passwordEncoder.matches(password, "$2a$10$4cKvOUqkKaVEbGTKW1V.uOhuYcIuFTJDtpk3Cz4d.MUxo0vQyXyN2")) {
            throw new BadCredentialsException("密码不正确！");
        }
        GrantedAuthority grantedAuthority = (GrantedAuthority) () -> "ROLE_SUPER_ADMIN";
        List<GrantedAuthority> grantedAuthorities = Arrays.asList(grantedAuthority);
        return new UsernamePasswordAuthenticationToken("admin", "123", grantedAuthorities);
    }



}
