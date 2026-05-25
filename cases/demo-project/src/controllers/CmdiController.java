package com.example.demo.controllers;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import javax.servlet.http.HttpServletRequest;

@RestController
public class CmdiController {

    @GetMapping("/cmdi1")
    public String cmdi1(HttpServletRequest request) {
        String cmd = request.getParameter("cmd");
        Runtime.getRuntime().exec(cmd);
        return "Executed";
    }

    @GetMapping("/cmdi2")
    public String cmdi2(HttpServletRequest req) {
        String header = req.getHeader("X-Command");
        new ProcessBuilder(header).start();
        return "Processed";
    }
}
