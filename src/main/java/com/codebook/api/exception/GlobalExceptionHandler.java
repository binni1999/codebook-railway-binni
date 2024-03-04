package com.codebook.api.exception;

import java.time.LocalDateTime;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;

@ControllerAdvice
public class GlobalExceptionHandler {

	private static final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

	@ExceptionHandler(UserException.class)
	public ResponseEntity<ErrorDto> UserExceptionHandler(UserException ue, WebRequest req) {
		ErrorDto error = new ErrorDto();
		error.setTimestamp(LocalDateTime.now());
		error.setMessage(ue.getMessage());
		error.setDetails(req.getDescription(false));
		return new ResponseEntity<ErrorDto>(error, HttpStatus.BAD_REQUEST);
	}

}
