package com.example.vuln.controllers;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import java.io.File;
import java.nio.file.Files;

@RestController
public class FileController {

    @GetMapping("/download")
    public byte[] download(@RequestParam String filename) throws Exception {
        File file = new File("/data/files/" + filename);
        return Files.readAllBytes(file.toPath());
    }

    @GetMapping("/read")
    public String read(@RequestParam String path) throws Exception {
        return new String(Files.readAllBytes(new File(path).toPath()));
    }
}
