package com.abhi.blog.repository;

import java.util.List;

import com.abhi.blog.entities.Post;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface PostRepository extends JpaRepository<Post, Integer>,JpaSpecificationExecutor<Post> {

	@Query("select distinct post from Post post where is_published = true")
	Page<Post> findAll(Pageable pageable);

	@Query(value = "select distinct author from posts", nativeQuery = true)
	public List<String> getAllAuthors();

	public List<Post> findAllByOrderByPublishedAtDesc();

	public List<Post> findAllByTagsName(String name);
	
	@Query("select post from Post post where user_id = :userId and is_published = false")
	List<Post> findDraftsByUId(@Param("userId") int userId);

}
