package com.abhi.blog.service;

import java.util.List;

import com.abhi.blog.entities.Tag;

public interface TagService {
	public Tag getTagByName(String tagName);
	public List<String> getAlltag();
}
