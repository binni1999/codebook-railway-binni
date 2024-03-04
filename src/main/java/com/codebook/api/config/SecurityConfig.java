package com.codebook.api.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.codebook.api.jwt.JwtAuthenticationFilter;


@Configuration
public class SecurityConfig {

	@Autowired
	private JwtAuthenticationFilter filter;

	@Autowired
	private UserDetailsService userDetailsService;

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	

	@Bean
	public DaoAuthenticationProvider daoAuthenticationProvider() {
		DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
		authenticationProvider.setUserDetailsService(userDetailsService);
		authenticationProvider.setPasswordEncoder(passwordEncoder());
		return authenticationProvider;
	}

	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration builder) throws Exception {
		return builder.getAuthenticationManager();
	}

	@Bean
	public SecurityFilterChain securityConfiguration(HttpSecurity http) throws Exception {
		http.csrf(c -> c.disable())
		.cors(Customizer.withDefaults())
				.authorizeHttpRequests(
						auth -> auth.requestMatchers("/orders/**").authenticated()
						.requestMatchers("/users/**").authenticated()
						.anyRequest().permitAll())
				.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
		http.addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class);
//		http.cors(c -> c.configurationSource(new CorsConfigurationSource() {
//
//			@Override
//			public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
//				CorsConfiguration cfg = new CorsConfiguration();
//				cfg.setAllowedOrigins(Arrays.asList("https://pankaj-code.netlify.app","https://binni-codebook.netlify.app/**", "https://binni-codebook.netlify.app"));
//				cfg.setAllowedMethods(Collections.singletonList("*"));
//				cfg.setAllowCredentials(true);
//				cfg.setAllowedHeaders(Collections.singletonList("*"));
//				cfg.setExposedHeaders(Arrays.asList("Authorization","Access-Control-Allow-Origin"));
//				cfg.setMaxAge(3600L);
//				return cfg;
//			}
//		}));
		return http.build();
	}
}
