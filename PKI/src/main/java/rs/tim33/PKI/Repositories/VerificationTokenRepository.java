package rs.tim33.PKI.Repositories;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

import rs.tim33.PKI.Models.VerificationToken;


public interface VerificationTokenRepository extends JpaRepository<VerificationToken, Long> {
    Optional<VerificationToken> findByToken(String token);
}
