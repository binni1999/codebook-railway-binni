package com.codebook.api.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.codebook.api.entity.Product;
import com.codebook.api.repository.ProductRepository;

@Service
public class ProductService {

	@Autowired
	private ProductRepository repo;

	public Product addProduct(Product product) {

		Product newProduct = repo.save(product);
		return newProduct;
	}

	public List<Product> getAllProducts() {
		List<Product> allProducts = repo.findAll();
		return allProducts;
	}

	public Product getProduct(Integer id) {
		return repo.findById(id).get();
	}

	public List<Product> getBestSellerBooks() {
		List<Product> getAllBooks = repo.findBestSellerBooks();
		return getAllBooks;
	}

	public Product updateProduct(Product productInRequest, Integer id) throws Exception {
		Product productInDb = repo.findById(id).get();
		if (productInDb == null) {
			throw new Exception("There is no product available with the given id " + id);
		} else {
			if (productInRequest.getName() != null) {
				productInDb.setName(productInRequest.getName());
			}
			if (productInRequest.getOverview() != null) {
				productInDb.setOverview(productInRequest.getOverview());
			}
			if (productInRequest.getLongDescription() != null) {
				productInDb.setLongDescription(productInRequest.getLongDescription());
			}
			if (productInRequest.getPoster() != null) {
				productInDb.setPoster(productInRequest.getPoster());
			}
			if (productInRequest.isBestSeller()) {
				productInDb.setBestSeller(productInRequest.isBestSeller());
			}
			if (productInRequest.isInStock()) {
				productInDb.setInStock(productInRequest.isInStock());
			}
			if (productInRequest.getImageLocal() != null) {
				productInDb.setImageLocal(productInRequest.getImageLocal());
			}

			if (productInRequest.getPrice() > 0) {
				productInDb.setPrice(productInRequest.getPrice());
			}

			if (productInRequest.getRating() != null) {
				productInDb.setRating(productInRequest.getRating());
			}

			return repo.save(productInDb);
		}
	}

	public String deleteProduct(Integer id) {
		repo.deleteById(id);
		return "The product has been deleted with the given id: " + id;
	}
	
	public List<Product> searchProductsByName(String keyword){
		if(keyword==null || keyword=="" || keyword==" ") {
			return repo.findAll();
		}
		List<Product> products = repo.findProductsByKeyword(keyword);
		return products;
	}
	public List<Product> products (){
		return repo.findAll();
	}
}
