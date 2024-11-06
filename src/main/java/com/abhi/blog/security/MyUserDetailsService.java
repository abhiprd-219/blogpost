package com.abhi.blog.security;

import com.abhi.blog.entities.User;
import com.abhi.blog.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class MyUserDetailsService implements UserDetailsService {

	@Autowired
    UserService userService;
	@Override
	public UserDetails loadUserByUsername(String userEmail) throws UsernameNotFoundException {
		
		User user = userService.getUserByEmail(userEmail);
		
		if(user == null)
			throw new UsernameNotFoundException("user not found");
		
		
		return new UserPrincipal(user);
	}

}
