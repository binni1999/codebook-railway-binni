package com.codebook.api.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import com.codebook.api.entity.Order;

public interface OrderRepository extends JpaRepository<Order, Integer> {

	@Query("Select o from Order o where o.user.id = ?1")
	public List<Order> findOrdersByUserId(Integer id);
}
