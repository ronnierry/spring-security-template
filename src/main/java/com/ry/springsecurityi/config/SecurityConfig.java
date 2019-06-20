package com.ry.springsecurityi.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;

@EnableGlobalMethodSecurity(securedEnabled = true)
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    ObjectMapper objectMapper;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers(
                        "/ajax-login",
                        "/csrf"
                )
                .permitAll()
                // 特殊的权限校验可以修改这里
                .anyRequest()
                .authenticated()
                .and()
                // 添加自定义登陆过滤器
                .addFilterBefore(customizedAuthenticationProcessingFilter(), UsernamePasswordAuthenticationFilter.class)
                .logout()
                .logoutUrl("/logout")
                .logoutSuccessHandler(
                        (HttpServletRequest request, HttpServletResponse response, Authentication authentication) -> {
                            HashMap<String, Object> data = new HashMap<>();
                            data.put("success", true);
                            objectMapper.writeValue(response.getWriter(), data);
                        })
                .permitAll()
                .and().csrf().csrfTokenRepository(csrfTokenRepository())
        //.and().addFilterAfter()
        ;

    }

    @Bean
    public CustomizedAuthenticationProcessingFilter customizedAuthenticationProcessingFilter() {
        CustomizedAuthenticationProcessingFilter customizedAuthenticationProcessingFilter = new CustomizedAuthenticationProcessingFilter();
        customizedAuthenticationProcessingFilter.setAuthenticationFailureHandler(
                (request, response, exception) -> {
                    response.setContentType("application/json; charset=utf-8");
                    HashMap<String, Object> data = new HashMap<>(2);
                    data.put("success", false);
                    data.put("msg", exception.getMessage());
                    objectMapper.writeValue(response.getWriter(), data);
                }
        );

        customizedAuthenticationProcessingFilter.setAuthenticationSuccessHandler(
                (request, response, authentication) -> {
                    response.setContentType("application/json; charset=utf-8");
                    HashMap<String, Object> data = new HashMap<>(2);
                    data.put("success", true);
                    data.put("msg", authentication.getPrincipal());
                    objectMapper.writeValue(response.getWriter(), data);
                }
        );
        return customizedAuthenticationProcessingFilter;
    }

    @Bean
    public HttpSessionCsrfTokenRepository csrfTokenRepository() {
        HttpSessionCsrfTokenRepository csrfTokenRepository = new HttpSessionCsrfTokenRepository();
        csrfTokenRepository.setSessionAttributeName("X-CSRF-TOKEN");
        return csrfTokenRepository;
    }
}
