package com.codebook.api.exception;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import lombok.Data;

@Data
public class ErrorDto {

	private String message;
	private String details;
	private LocalDateTime timestamp;
}
