package com.abhi.blog.repository;

import com.abhi.blog.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Integer> {

	User findByEmail(String usreName);
}
