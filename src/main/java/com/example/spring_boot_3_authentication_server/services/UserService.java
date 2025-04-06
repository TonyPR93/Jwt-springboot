package com.example.spring_boot_3_authentication_server.services;

import java.time.LocalDateTime;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.example.spring_boot_3_authentication_server.models.User;
import com.example.spring_boot_3_authentication_server.repositories.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class UserService {
	private final UserRepository userRepository;
	
	public UserDetailsService userDetailsService() {
		return new UserDetailsService() {
			
			@Override
			public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
				// TODO Auto-generated method stub
				return userRepository.findByEmail(username).orElseThrow(()-> new UsernameNotFoundException("Username not found"));
			}
		};
	}
	
	public User save(User newUser) {
		if (newUser.getId() == null) {
			newUser.setCreatedAt(LocalDateTime.now());
		}
		newUser.setUpdatedAt(LocalDateTime.now());
		return userRepository.save(newUser);
	}
}
