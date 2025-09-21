package rs.tim33.PKI.Services;

import java.util.Collections;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import rs.tim33.PKI.Models.UserModel;
import rs.tim33.PKI.Repositories.UserRepository;

@Service
public class CustomUserDetailsService implements UserDetailsService{
	@Autowired
	private UserRepository userRepo;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		UserModel user = userRepo.findByEmail(username).orElseThrow(() -> new UsernameNotFoundException("No user with that email"));
		
		return new User(user.getEmail(), user.getPasswordHash(), Collections.emptyList());
	}
	
}
