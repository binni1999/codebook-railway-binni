package com.codebook.api.order;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase.Replace;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.test.annotation.Rollback;

import com.codebook.api.entity.CartItem;
import com.codebook.api.entity.Order;
import com.codebook.api.entity.Product;
import com.codebook.api.entity.User;
import com.codebook.api.repository.CartItemRepository;
import com.codebook.api.repository.OrderRepository;
import com.codebook.api.repository.ProductRepository;
import com.codebook.api.repository.UserRepository;

@DataJpaTest
@AutoConfigureTestDatabase(replace = Replace.NONE)
@Rollback(false)
public class OrderRepositoryTests {

	@Autowired
	private CartItemRepository cartRepo;
	@Autowired
	private ProductRepository productRepository;
	@Autowired
	private UserRepository userRepository;
	@Autowired
	private OrderRepository repo;

	@Test
	public void add() {
		User user = userRepository.findById(2).get();
		Product pro = productRepository.findById(1).get();
		CartItem cart = new CartItem();
		cart.setUser(user);
		cart.setProduct(pro);
		CartItem saved = cartRepo.save(cart);
		assertThat(saved).isNotNull();
	}

	@Test
	public void createOrder() {
		Order order = new Order();
		User user = userRepository.findById(2).get();
		List<CartItem> carts = cartRepo.findByUser(user);
		order.setAmountPaid(120);
		order.setQuantity(3);
		order.setUser(user);
		for (CartItem item : carts) {
			order.getCartItem().add(item);
		}
		Order newOrder = repo.save(order);
		assertThat(newOrder).isNotNull();

	}
}
