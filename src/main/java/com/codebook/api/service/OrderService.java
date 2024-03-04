package com.codebook.api.service;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.codebook.api.entity.CartItem;
import com.codebook.api.entity.Order;
import com.codebook.api.entity.Product;
import com.codebook.api.entity.User;
import com.codebook.api.models.OrderModel;
import com.codebook.api.repository.CartItemRepository;
import com.codebook.api.repository.OrderRepository;
import com.codebook.api.repository.ProductRepository;
import com.codebook.api.repository.UserRepository;

@Service
public class OrderService {
	Logger logger = LoggerFactory.getLogger(OrderService.class);

	@Autowired
	private OrderRepository orderRepository;

	@Autowired
	private ProductRepository productRepository;
	@Autowired
	private UserRepository userRepository;
	@Autowired
	private CartItemRepository cartItemRepository;

	public Order createOrder(OrderModel order) {

		User user = userRepository.findById(order.getUser().getId()).get();
		Order newOrder = new Order();
		newOrder.setQuantity(order.getQuantity());
		newOrder.setAmountPaid(order.getAmountPaid());
		newOrder.setUser(user);
		for (Product product : order.getProducts()) {
			CartItem cart = new CartItem();
			cart.setUser(user);
			Product p = productRepository.findById(product.getId()).get();
			cart.setProduct(product);
			cartItemRepository.save(cart);
			newOrder.getCartItem().add(cart);
		}
		orderRepository.save(newOrder);
		return newOrder;

	}

	public List<Order> getUserOrders(Integer userId) {

		return orderRepository.findOrdersByUserId(userId);

	}
}
