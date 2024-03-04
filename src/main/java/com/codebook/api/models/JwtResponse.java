package com.codebook.api.models;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class JwtResponse {

	public String jwtToken;
	public String username;
	public Integer id;
}
