package com.abhi.blog.service;

import java.util.List;

import org.springframework.data.domain.Page;
import org.springframework.data.jpa.domain.Specification;

import com.abhi.blog.entities.Post;

public interface PostService {
	public Post savePost(Post post);

	public Post getPostById(int id);

	public void deletePost(Post post);
	
	public List<Post> getDraftsOfUser(int id);

	public Page<Post> getAllPostsOfPage(int start, int limit);

	public List<String> getAllAuthor();

	public List<Post> getAllPosts();

	public Page<Post> getSortedPosts(int start, int limit, String column, String basic);
	
	public Page<Post> getSearchAndFilterResult(Specification<Post> specification, int start, int limit);
}
