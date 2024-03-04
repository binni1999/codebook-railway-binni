package com.codebook.api.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.codebook.api.entity.CartItem;
import com.codebook.api.entity.User;

public interface CartItemRepository extends JpaRepository<CartItem, Integer> {

	public List<CartItem> findByUser(User user);
}
