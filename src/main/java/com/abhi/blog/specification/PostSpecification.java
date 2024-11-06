package com.abhi.blog.specification;

import java.util.List;

import javax.persistence.criteria.CriteriaBuilder;
import javax.persistence.criteria.CriteriaQuery;
import javax.persistence.criteria.Join;
import javax.persistence.criteria.JoinType;
import javax.persistence.criteria.Predicate;
import javax.persistence.criteria.Root;

import com.abhi.blog.entities.Post;
import com.abhi.blog.entities.Tag;
import org.springframework.data.jpa.domain.Specification;


public class PostSpecification implements Specification<Post> {

	private static final long serialVersionUID = 1L;

	@Override
	public Predicate toPredicate(Root<Post> root, CriteriaQuery<?> query, CriteriaBuilder criteriaBuilder) {

		return null;
	}

	public static Specification<Post> getPublishedPost() {
		return (root, query, criteriaBuilder) -> {
			query.distinct(true);
			return criteriaBuilder.equal(root.<Boolean>get("isPublished"), true);
		};
	}

	public static Specification<Post> getBySearchArg(String searchArg) {
		return (root, query, criteriaBuilder) -> {
			query.distinct(true);
			if (searchArg == null) {
				return criteriaBuilder.conjunction();
			}
			Predicate inTitle = criteriaBuilder.like(criteriaBuilder.upper(root.<String>get("title")),
					"%" + searchArg + "%");
			Predicate inContent = criteriaBuilder.like(criteriaBuilder.upper(root.<String>get("content")),
					"%" + searchArg + "%");
			Predicate inAuthor = criteriaBuilder.like(criteriaBuilder.upper(root.<String>get("author")),
					"%" + searchArg + "%");

			Join<Post, Tag> postTags = root.join("tags", JoinType.INNER);
			Predicate inTags = criteriaBuilder.like(criteriaBuilder.upper(postTags.<String>get("name")),
					"%" + searchArg + "%");

			return criteriaBuilder.or(inTitle, inContent, inAuthor, inTags);
		};
	}

	public static Specification<Post> getByAuthor(List<String> authorsName) {
		return (root, query, criteriaBuilder) -> {
			query.distinct(true);
			if (authorsName == null || authorsName.isEmpty()) {
				return criteriaBuilder.conjunction();
			}

			return root.<String>get("author").in(authorsName);
		};
	}

	public static Specification<Post> getByTags(List<String> tags) {
		return (root, query, criteriaBuilder) -> {
			query.distinct(true);
			if (tags == null || tags.isEmpty()) {
				return criteriaBuilder.conjunction();
			}
			Join<Post, Tag> postTags = root.join("tags", JoinType.INNER);
			return postTags.<String>get("name").in(tags);
		};
	}
	

	public static Specification<Post> findSearchAndFiltredResult(String search, List<String> authorsName, List<String> tags) {
		return   getPublishedPost().and(getBySearchArg(search)).and(getByAuthor(authorsName)).and(getByTags(tags));
	}

}
