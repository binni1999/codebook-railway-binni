package com.codebook.api.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.codebook.api.entity.Product;
import com.codebook.api.service.ProductService;

@RestController
@RequestMapping("/products/search")
public class SearchController {
	@Autowired
	private ProductService service;
	
	@GetMapping
	public ResponseEntity<?> search(){
		try {
			List<Product> products = service.products();
			return ResponseEntity.ok(products);
		} catch (Exception e) {
			return ResponseEntity.noContent().build();
		}
		}

	@GetMapping("/{keyword}")
	public ResponseEntity<?> searchProducts(@PathVariable String keyword ){
	try {
		List<Product> products = service.searchProductsByName(keyword);
		return ResponseEntity.ok(products);
	} catch (Exception e) {
		return ResponseEntity.noContent().build();
	}
	}

}
