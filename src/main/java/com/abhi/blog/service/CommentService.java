package com.abhi.blog.service;

import com.abhi.blog.entities.Comment;

public interface CommentService {
	public Comment getCommentById(int id);
	public void saveComment(Comment comment);
	public void deleteCommentById(int id);

}
