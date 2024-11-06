package com.abhi.blog.controller;

import java.util.Arrays;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import com.abhi.blog.entities.Post;
import com.abhi.blog.entities.User;
import com.abhi.blog.service.PostService;
import com.abhi.blog.service.TagService;
import com.abhi.blog.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import com.abhi.blog.specification.PostSpecification;


@Controller
public class HomeControler {

	@Autowired
	private PostService postService;

	@Autowired
	private TagService tagService;

	@Autowired
	private UserService userService;

	@RequestMapping(value = { "/", "/posts" })
	public ModelAndView getPages(HttpServletRequest request) {
		ModelAndView modelAndView = new ModelAndView();
		int start = 0;
		int limit = 4;

		Page<Post> postList;
		if (request.getParameter("pageNumber") == null) {
			postList = postService.getAllPostsOfPage(start, limit);
			modelAndView.addObject("pageNumber", start);
			modelAndView.addObject("postList", postList);
			modelAndView.addObject("totalPages", postList.getTotalPages());
		}
		if (request.getParameter("pageNumber") != null) {
			start = Integer.parseInt(request.getParameter("pageNumber"));
			postList = postService.getAllPostsOfPage(start, limit);
			modelAndView.addObject("postList", postList);
			modelAndView.addObject("pageNumber", start);
			modelAndView.addObject("totalPages", postList.getTotalPages());
		}

		modelAndView.addObject("authorList", postService.getAllAuthor());
		modelAndView.addObject("tagsList", tagService.getAlltag());
		modelAndView.addObject("limit", limit);
		modelAndView.setViewName("indexpage");

		return modelAndView;
	}

	@RequestMapping(value = { "/posts/searchedposts" }, method = RequestMethod.GET)
	public ModelAndView getSearchedPosts(@RequestParam(required = false, value = "searchArg") String searchArg,
										 @RequestParam(required = false, value = "tagName") String tags,
										 @RequestParam(required = false, value = "authorName") String authors,
										 @RequestParam(required = false, value = "pageNumber")String pageNumber)

	{
		ModelAndView modelAndView = new ModelAndView();
		modelAndView.addObject("searchArg", searchArg);
		modelAndView.addObject("tagName", tags);
		modelAndView.addObject("authorName", authors);



		int start = (pageNumber == null)? 0 :(pageNumber.length() < 1) ? 0 :Integer.parseInt(pageNumber);
		int limit = 4;
		Page<Post> postList = null;

		searchArg = (searchArg == null)? null : (searchArg.length() < 1)?null: searchArg.toUpperCase();
		tags = (tags == null)? null : (tags.length() < 1)? null : tags;
		authors = (authors == null )? null : (authors.length() < 1)?null : authors;

		List<String> filtredTags = null;
		filtredTags = (tags == null)? null : Arrays.asList(tags.split(","));

		List<String> filtredAuthors = null;
		filtredAuthors = (authors == null)? null : Arrays.asList(authors.split(","));




		postList = postService.getSearchAndFilterResult(PostSpecification.findSearchAndFiltredResult(searchArg, filtredAuthors, filtredTags), start, limit);

		modelAndView.addObject("authorList", postService.getAllAuthor());
		modelAndView.addObject("tagsList", tagService.getAlltag());
		modelAndView.addObject("limit", limit);
		modelAndView.setViewName("searchresultpage");
		modelAndView.addObject("postList", postList);
		modelAndView.addObject("pageNumber", start);
		modelAndView.addObject("totalPages", postList.getTotalPages());

		return modelAndView;

	}

	String arrayToString(String[] args) {
		String result = "";
		for (String arg : args) {
			result += arg + ",";
		}
		return result.substring(0, result.length() - 1);
	}

	@RequestMapping(value = { "/posts/{id}" }, method = RequestMethod.GET)
	public ModelAndView readFulPost(@PathVariable("id") int id) {
		ModelAndView modelAndView = new ModelAndView();
		Post post = postService.getPostById(id);

		modelAndView.addObject("post", post);
		modelAndView.setViewName("fullcontentpage");

		return modelAndView;
	}

	@RequestMapping(value = { "/user/{uid}/drafts" }, method = RequestMethod.GET)
	public ModelAndView getDrafts(@PathVariable("uid") int userId) {
		ModelAndView modelAndView = new ModelAndView();

		modelAndView.addObject("postList", postService.getDraftsOfUser(userId));
		modelAndView.setViewName("draftspage");

		return modelAndView;
	}

	@RequestMapping(value = { "/posts/olderposts" }, method = RequestMethod.GET)
	public ModelAndView getSortedHomePageDesc(HttpServletRequest request) {
		ModelAndView modelAndView = new ModelAndView();

		int start = 0;
		int limit = 4;

		Page<Post> postList = null;

		if (request.getParameter("pageNumber") == null) {
			postList = postService.getSortedPosts(start, limit, "publishedAt", "ASC");
		}
		if (request.getParameter("pageNumber") != null) {
			start = Integer.parseInt(request.getParameter("pageNumber"));
			postList = postService.getSortedPosts(start, limit, "publishedAt", "ASC");
		}

		modelAndView.addObject("postList", postList);
		modelAndView.addObject("pageNumber", start);
		modelAndView.addObject("totalPages", postList.getTotalPages());
		modelAndView.addObject("authorList", postService.getAllAuthor());
		modelAndView.addObject("tagsList", tagService.getAlltag());
		modelAndView.addObject("limit", limit);
		modelAndView.setViewName("indexpage");

		return modelAndView;
	}

	@RequestMapping(value = { "/posts/recentposts" }, method = RequestMethod.GET)
	public ModelAndView getSortedHomePageAsc(HttpServletRequest request) {
		ModelAndView modelAndView = new ModelAndView();

		int start = 0;
		int limit = 4;

		Page<Post> postList = null;
		if (request.getParameter("pageNumber") == null) {
			postList = postService.getSortedPosts(start, limit, "publishedAt", "DESC");
		}
		if (request.getParameter("pageNumber") != null) {
			start = Integer.parseInt(request.getParameter("pageNumber"));
			postList = postService.getSortedPosts(start, limit, "publishedAt", "DESC");
		}

		modelAndView.addObject("postList", postList);
		modelAndView.addObject("pageNumber", start);
		modelAndView.addObject("totalPages", postList.getTotalPages());
		modelAndView.addObject("authorList", postService.getAllAuthor());
		modelAndView.addObject("tagsList", tagService.getAlltag());
		modelAndView.addObject("limit", limit);
		modelAndView.setViewName("indexpage");

		return modelAndView;
	}

	@RequestMapping("/login")
	public ModelAndView getLoginForm() {
		ModelAndView modelAndView = new ModelAndView();

		modelAndView.setViewName("loginsinguppage");

		return modelAndView;
	}

	@RequestMapping(value = { "/singup/adduser" }, method = RequestMethod.POST)
	public ModelAndView addUser(User user) {
		User newUser = new User();
		newUser.setName(user.getName());
		newUser.setEmail(user.getEmail());
		newUser.setPassword(user.getPassword());
		newUser.setRole("AUTHOR");
		userService.saveOrUpdateUserDetails(newUser);

		return new ModelAndView("redirect:/");
	}




}