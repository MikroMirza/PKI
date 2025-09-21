package rs.tim33.PKI.Repositories;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import rs.tim33.PKI.Models.AliasKey;

@Repository
public interface KeystoreRepository extends JpaRepository<AliasKey, Long>{
	Optional<AliasKey> findByAlias(String alias);
}
