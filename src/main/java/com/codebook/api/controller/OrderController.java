package com.codebook.api.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.codebook.api.entity.Order;
import com.codebook.api.models.OrderModel;
import com.codebook.api.service.OrderService;

@RestController
@RequestMapping("/orders")
public class OrderController {

	@Autowired
	private OrderService service;

	@PostMapping("/create")
	public ResponseEntity<?> createOrder(@RequestBody OrderModel order) {
		Order orderSaved = service.createOrder(order);
		return ResponseEntity.ok(orderSaved);
	}

	@GetMapping("/{id}")
	public ResponseEntity<?> getUserOrders(@PathVariable Integer id) {
		List<Order> orders = service.getUserOrders(id);
		return ResponseEntity.ok(orders);
	}
}
