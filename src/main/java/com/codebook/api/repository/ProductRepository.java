package com.codebook.api.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import com.codebook.api.entity.Product;

public interface ProductRepository extends JpaRepository<Product, Integer> {

	@Query("Select p from Product p where p.bestSeller = true")
	public List<Product> findBestSellerBooks();
	
	@Query("Select p from Product p where p.name like %?1% or p.overview like %?1% ")
	public List<Product> findProductsByKeyword(String keyword);
}
