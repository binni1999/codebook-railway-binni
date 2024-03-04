package com.codebook.api.controller;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.codebook.api.entity.Product;
import com.codebook.api.service.ProductService;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/products")
public class ProductAPIController {

	@Autowired
	private ProductService service;

	@PostMapping("/add")
	public ResponseEntity<?> addNewProduct(@RequestBody Product product) {
		try {

			Product newProduct = service.addProduct(product);
			return ResponseEntity.ok(newProduct);
		} catch (Exception e) {
			return ResponseEntity.internalServerError().build();
		}
	}

	@GetMapping
	public ResponseEntity<?> getAllProducts() {
		try {
			List<Product> allProducts = service.getAllProducts();
			return ResponseEntity.ok(allProducts);
		} catch (Exception e) {
			return ResponseEntity.internalServerError().build();
		}
	}

	@GetMapping("/best_seller")
	public ResponseEntity<?> findBestSeller() {
		try {
			List<Product> allProducts = service.getBestSellerBooks();
			return ResponseEntity.ok(allProducts);
		} catch (Exception e) {
			return ResponseEntity.internalServerError().build();
		}
	}

	@GetMapping("/{id}")
	public ResponseEntity<?> getProductById(@PathVariable Integer id) {
		try {
			return ResponseEntity.ok(service.getProduct(id));
		} catch (Exception e) {
			return ResponseEntity.internalServerError().build();
		}
	}

	@PutMapping("/update/{id}")
	public ResponseEntity<?> updateProduct(@PathVariable Integer id, @RequestBody @Valid Product product) {
		try {
			Product productUpdated = service.updateProduct(product, id);
			return ResponseEntity.ok(productUpdated);
		} catch (Exception e) {
			return ResponseEntity.internalServerError().build();
		}
	}

	@DeleteMapping("/{id}")
	public ResponseEntity<?> deleteProduct(@PathVariable Integer id) {
		try {
			String msg = service.deleteProduct(id);
			return ResponseEntity.ok(msg);
		} catch (Exception e) {
			return ResponseEntity.internalServerError().build();
		}
	}

	@GetMapping("/featured_Products")
	public ResponseEntity<?> getFeaturedProducts() {
		try {
			List<Product> products = new ArrayList<>();
			Integer[] arr = new Integer[] { 4, 6, 8 };
			for (int i = 0; i < arr.length; i++) {
				Product p = service.getProduct(arr[i]);
				products.add(p);
			}
			return ResponseEntity.ok(products);
		} catch (Exception e) {
			return ResponseEntity.internalServerError().build();
		}

	}

}
