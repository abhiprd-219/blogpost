package com.abhi.blog.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.abhi.blog.entities.Comment;
import com.abhi.blog.repository.CommentRepository;

@Service
public class CommentServiceImplementation implements CommentService {

	@Autowired
	private CommentRepository commentRepository;
	@Override
	public Comment getCommentById(int id) {
		Comment comment = commentRepository.findById(id).orElse(null);
		return comment;
	}
	@Override
	public void saveComment(Comment comment) {
		commentRepository.save(comment);
		
	}
	@Override
	public void deleteCommentById(int id) {
		commentRepository.deleteById(id);
		
	}

}
