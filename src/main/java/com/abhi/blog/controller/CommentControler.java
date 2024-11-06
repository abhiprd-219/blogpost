package com.abhi.blog.controller;

import java.util.Date;

import com.abhi.blog.entities.Comment;
import com.abhi.blog.entities.Post;
import com.abhi.blog.service.CommentService;
import com.abhi.blog.service.PostService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

@Controller
public class CommentControler {

	@Autowired
	private PostService postService;

	@Autowired
	private CommentService commentService;

	@RequestMapping(value = { "/posts/{id}/addcomment/savecomment" }, method = RequestMethod.POST)
	public ModelAndView saveNewComment(@RequestParam("name") String name, @RequestParam("email") String email,
			@RequestParam("comment") String comment, @PathVariable("id") int postId) {
		Post post = postService.getPostById(postId);

		Comment newComment = new Comment();

		newComment.setName(name);
		newComment.setEmail(email);
		newComment.setComment(comment);
		newComment.setCreatedAt(new Date());
		newComment.setUpdatedAt(new Date());
		newComment.setPost(post);
		post.getComments().add(newComment);

		postService.savePost(post);

		return new ModelAndView("redirect:/posts/" + postId);
	}

	@RequestMapping(value = { "/posts/{id}/{commentid}/updatecomment" }, method = RequestMethod.GET)
	public ModelAndView getCommentUpdatePage(@PathVariable("commentid") int commentId, @PathVariable("id") int postId) {
		Comment comment = commentService.getCommentById(commentId);
		if (comment == null) {
			return new ModelAndView("redirect:/posts/" + postId);
		}

		ModelAndView modelAndView = new ModelAndView();
		modelAndView.addObject("comment", comment);
		modelAndView.addObject("postId", postId);
		modelAndView.setViewName("commentform");

		return modelAndView;
	}

	@RequestMapping(value = { "/posts/{id}/{commentid}/updatecomment/savecomment" }, method = RequestMethod.POST)
	public ModelAndView saveUpdatedComment(@PathVariable("commentid") int commentId, @PathVariable("id") int postId,
			@RequestParam("name") String name, @RequestParam("email") String email,
			@RequestParam("comment") String comment) {

		Comment previousComment = commentService.getCommentById(commentId);

		previousComment.setName(name);
		previousComment.setEmail(email);
		previousComment.setComment(comment);
		previousComment.setUpdatedAt(new Date());

		commentService.saveComment(previousComment);
		return new ModelAndView("redirect:/posts/" + postId);

	}

	@RequestMapping(value = { "/posts/{id}/{commentid}/deletecomment" }, method = RequestMethod.POST)
	public ModelAndView deleteComment(@PathVariable("commentid") int commentId, @PathVariable("id") int postId) {
		
		commentService.deleteCommentById(commentId);

		return new ModelAndView("redirect:/posts/" + postId);
	}

}