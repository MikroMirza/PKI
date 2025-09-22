package rs.tim33.PKI.Utils;

import java.util.Collection;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import rs.tim33.PKI.Models.Role;
import rs.tim33.PKI.Models.UserModel;
import rs.tim33.PKI.Repositories.UserRepository;

@Component
public class LoggedUserUtils {
	@Autowired
	private UserRepository userRepo;
	
	public Boolean isLoggedIn() {
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		
		if(auth == null || auth instanceof AnonymousAuthenticationToken)
			return false;
		else
			return true;
	}
	
	public Role getLoggedInRole() {
		if(!isLoggedIn())
			return null;
		UserModel user = userRepo.findByEmail(SecurityContextHolder.getContext().getAuthentication().getName()).orElseGet(null);
		if (user != null)
			return user.getRole();
		return null;
	}
	
	public String getLoggedInOrganization() {
		if(!isLoggedIn())
			return null;
		UserModel user = userRepo.findByEmail(SecurityContextHolder.getContext().getAuthentication().getName()).orElseGet(null);
		if (user != null)
			return user.getOrganization();
		return null;	
	}
	
	public UserModel getLoggedInUser() {
		return userRepo.findByEmail(SecurityContextHolder.getContext().getAuthentication().getName()).orElseGet(null);
	}
}
