package com.codebook.api.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import com.codebook.api.entity.User;
import com.codebook.api.jwt.JwtTokenHelper;
import com.codebook.api.models.JwtRequest;
import com.codebook.api.models.JwtResponse;
import com.codebook.api.models.UserLogged;
import com.codebook.api.service.UserService;

import jakarta.validation.Valid;

@RestController

public class UserAuthController {
	Logger logger = LoggerFactory.getLogger(UserAuthController.class);
	@Autowired
	private AuthenticationManager manager;
	@Autowired
	private JwtTokenHelper helper;
	@Autowired
	private UserDetailsService userDetailsService;

	@Autowired
	private UserService service;

	@PostMapping("/signup")
	public ResponseEntity<?> registerUser(@RequestBody @Valid User user) {
		try {
			User savedUser = service.registerUser(user);
			return ResponseEntity.ok(savedUser);
		} catch (Exception e) {
			return ResponseEntity.internalServerError().build();
		}
	}

	@PostMapping("/login")
	public ResponseEntity<JwtResponse> login(@RequestBody JwtRequest request) throws Exception {
		
		boolean user = service.userExistOrNot(request.getEmail());
		if(user) {
			this.doAuthenticate(request.getEmail(), request.getPassword());
			UserDetails userDetails = userDetailsService.loadUserByUsername(request.getEmail());
			String token = helper.generateToken(userDetails);
			UserLogged loggedUser = service.getUserByEmail(userDetails.getUsername());
			JwtResponse response = new JwtResponse(token, userDetails.getUsername(), loggedUser.getId());
			return new ResponseEntity<JwtResponse>(response, HttpStatus.OK);
		}
		else {
			return new ResponseEntity<JwtResponse>(new JwtResponse(null, null, null),HttpStatus.BAD_REQUEST);
		}
		

	}

	public void doAuthenticate(String email, String password) {
		UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(email,
				password);
		logger.info("authentication token {}",authenticationToken);
		try {
			manager.authenticate(authenticationToken);
		} catch (BadCredentialsException e) {
			throw new RuntimeException("Invalid Username or password");
		}
	}

	@GetMapping("/users/{id}")
	public ResponseEntity<?> getUser(@PathVariable Integer id) {
		try {

			return ResponseEntity.ok(service.getUserById(id));
		} catch (Exception e) {
			return ResponseEntity.internalServerError().build();
		}
	}

}
