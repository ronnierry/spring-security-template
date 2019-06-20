package com.ry.springsecurityi.controller;

import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequestMapping
@RestController
public class TestController {
    @Secured("ROLE_ADMIN")
    @GetMapping("/test-1")
    public String test(){
        return "test-get";
    }

    @Secured("ROLE_SUPER_ADMIN")
    @GetMapping("/test-2")
    public String testP(){
        return "test-post";
    }

    @GetMapping("/csrf")
    public String csrf(){
        return "/csrf";
    }

    @PostMapping("/csrf-post")
    public String csrfPost(){
        return "/csrf-post";
    }
}
