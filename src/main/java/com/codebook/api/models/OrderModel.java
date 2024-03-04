package com.codebook.api.models;

import java.util.ArrayList;
import java.util.List;

import com.codebook.api.entity.CartItem;
import com.codebook.api.entity.Product;
import com.codebook.api.entity.User;
import com.fasterxml.jackson.annotation.JsonProperty;

import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToMany;
import lombok.Data;

@Data
public class OrderModel {

	private Integer id;
	
	@JsonProperty("amount_paid")
	private int amountPaid;
	
	private int quantity;
	private User user;
	private List<Product> products = new ArrayList<>();
}
