package com.abhi.blog.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.abhi.blog.entities.User;
import com.abhi.blog.repository.UserRepository;

@Service
public class UserServiceImplementation implements UserService {

	@Autowired
	private UserRepository userRepository;
	
	@Override
	public List<User> getAllUserData() {
		
		return userRepository.findAll();
	}
	@Override
	public void saveOrUpdateUserDetails(User user) {
		userRepository.save(user);
		
	}

	@Override
	public User getUserByEmail(String email) {
		User user = userRepository.findByEmail(email);
		return user;
	}

	@Override
	public User getUserById(int id) {
		User user = userRepository.findById(id).orElse(null);
		return user;
	}
	@Override
	public void deleteUserBYId(int userId) {
		userRepository.deleteById(userId);
		
	}


}
