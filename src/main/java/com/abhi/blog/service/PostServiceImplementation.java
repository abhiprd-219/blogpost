package com.abhi.blog.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;

import com.abhi.blog.entities.Post;
import com.abhi.blog.repository.PostRepository;

@Service
public class PostServiceImplementation implements PostService {

	@Autowired
	private PostRepository postRepository;

	@Override
	public Post savePost(Post post) {
		Post createdPost = postRepository.save(post);
		return createdPost;

	}

	@Override
	public Post getPostById(int id) {
		Post post = postRepository.findById(id).orElse(null);
		return post;
	}

	@Override
	public void deletePost(Post post) {
		postRepository.delete(post);

	}

	@Override
	public Page<Post> getAllPostsOfPage(int start, int limit) {
		Page<Post> posts = postRepository.findAll(PageRequest.of(start, limit));
		return posts;
	}

	@Override
	public List<String> getAllAuthor() {
		List<String> authors = postRepository.getAllAuthors();
		return authors;
	}

	@Override
	public List<Post> getAllPosts() {
		List<Post> posts = postRepository.findAll();
		return posts;
	}

	@Override
	public Page<Post> getSortedPosts(int start, int limit, String column, String basic) {
		Page<Post> posts = null;
		if (basic.equals("ASC")) {
			posts = postRepository
					.findAll(PageRequest.of(start, limit, Sort.by(column).ascending()));
		} else if (basic.equals("DESC")) {
			posts = postRepository.findAll(
					PageRequest.of(start, limit,Sort.by(column).descending()));
		}
		return posts;
	}

	@Override
	public List<Post> getDraftsOfUser(int id) {
		List<Post> posts = postRepository.findDraftsByUId(id);
		return posts;
	}

	@Override
	public Page<Post> getSearchAndFilterResult(Specification<Post> specification, int start, int limit) {
		Page<Post> posts = postRepository.findAll(specification, PageRequest.of(start, limit));
		return posts;
	}

}
