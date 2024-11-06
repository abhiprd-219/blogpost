package com.abhi.blog.repository;

import java.util.List;

import com.abhi.blog.entities.Tag;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface TagRepository extends JpaRepository<Tag, Integer> {
	
	public Tag findByName(String tagName);
	
	@Query(value = "select name from tags" , nativeQuery = true)
	public List<String> getAllTags();

}
