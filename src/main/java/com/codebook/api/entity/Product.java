package com.codebook.api.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "products")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Data
public class Product {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Integer id;

	private String name;
	private String overview;
	@Column(length = 5000)
	@JsonProperty("long_description")
	private String longDescription;
	@NotNull
	private int price;
	@Column(length = 5000)
	private String poster;
	@JsonProperty("image_local")
	private String imageLocal;
	private String rating;
	@JsonProperty("in_stock")
	private boolean inStock;
	private int size;
	@JsonProperty("best_seller")
	private boolean bestSeller;

}
