package com.abhi.blog.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.abhi.blog.entities.Tag;
import com.abhi.blog.repository.TagRepository;

@Service
public class TagServiceImplementation implements TagService {

	@Autowired
	private TagRepository tagRepository;
	
	@Override
	public Tag getTagByName(String tagName) {
		
		Tag tag = tagRepository.findByName(tagName);
		
		return tag;
	}

	@Override
	public List<String> getAlltag() {
		List<String> allTags = tagRepository.getAllTags();
		return allTags;
	}

}
