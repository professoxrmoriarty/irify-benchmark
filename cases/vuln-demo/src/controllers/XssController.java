package com.example.vuln.controllers;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;

@RestController
public class XssController {

    @GetMapping("/comment")
    public void comment(@RequestParam String content, HttpServletResponse response) throws Exception {
        PrintWriter out = response.getWriter();
        out.write("<div>" + content + "</div>");
    }

    @GetMapping("/greet")
    public void greet(@RequestParam String name, HttpServletResponse response) throws Exception {
        PrintWriter out = response.getWriter();
        out.write("<h1>Hello, " + name + "!</h1>");
    }
}
