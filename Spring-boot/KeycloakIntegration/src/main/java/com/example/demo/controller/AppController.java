package com.example.demo.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/base")
public class AppController {

	@GetMapping(path = "/status")
	public String democontroller() {
		return "Application is UP";

	}

}
