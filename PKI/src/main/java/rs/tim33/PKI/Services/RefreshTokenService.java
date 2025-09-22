package rs.tim33.PKI.Services;

import java.time.Instant;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import rs.tim33.PKI.Models.RefreshToken;
import rs.tim33.PKI.Repositories.RefreshTokenRepository;
import rs.tim33.PKI.Repositories.UserRepository;

@Service
public class RefreshTokenService {
	@Value("${jwt.refreshExpirationMs}")
    private Long refreshTokenDurationMs;

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;

    public RefreshTokenService(RefreshTokenRepository repo, UserRepository userRepo) {
        this.refreshTokenRepository = repo;
        this.userRepository = userRepo;
    }

    public RefreshToken createRefreshToken(String email) {
        var token = new RefreshToken();
        token.setUser(userRepository.findByEmail(email).get());
        token.setExpiration(Instant.now().plusMillis(refreshTokenDurationMs));
        token.setToken(UUID.randomUUID().toString());
        
        refreshTokenRepository.findByUserEmail(email).ifPresent(t -> refreshTokenRepository.delete(t));
        
        return refreshTokenRepository.save(token);
    }

    public boolean isTokenExpired(RefreshToken token) {
        return token.getExpiration().isBefore(Instant.now());
    }
}
