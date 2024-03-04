package com.codebook.api.service;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.codebook.api.entity.User;
import com.codebook.api.exception.UserException;
import com.codebook.api.models.UserLogged;
import com.codebook.api.repository.UserRepository;

@Service
public class UserService {

	@Autowired
	private UserRepository repo;
	@Autowired
	private PasswordEncoder passwordEncoder;

	public User registerUser(User user) throws UserException {
		
		User newuser = new User();
		newuser.setEmail(user.getEmail());
		newuser.setName(user.getName());
		newuser.setPassword(passwordEncoder.encode(user.getPassword()));

		return repo.save(newuser);

	}
	public boolean userExistOrNot(String email) throws UserException {
		Optional<User> findByEmail = repo.findByEmail(email);
		if(!findByEmail.isEmpty()) {
			return true;
		}
		else {
			throw new UserException("No user present with the given userid");
		}
	}

	public UserLogged getUserByEmail(String email) throws UserException {
		try {
			User user = repo.findByEmail(email).get();
			
			if (user != null) {
				UserLogged loggedUser = new UserLogged();
				loggedUser.setEmail(user.getEmail());
				loggedUser.setName(user.getName());
				loggedUser.setId(user.getId());
				return loggedUser;
			} else {
				throw new UserException("No user is present with the given id");
			}
		} catch (Exception e) {
			throw new UserException("No user is present with the given id");
		}
	}

	public User getUserById(Integer id) throws UserException {
		try {
			User user = repo.findById(id).get();
			if (user != null) {
				return user;
			} else {
				throw new UserException("No user is present with the given id");
			}
		} catch (Exception e) {
			throw new UserException("No user is present with the given id");
		}
	}

}
