package rs.tim33.PKI.Repositories;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import rs.tim33.PKI.Models.CertificateModel;
import rs.tim33.PKI.Models.KeystoreModel;

@Repository
public interface KeystoreRepository extends JpaRepository<KeystoreModel, Long>{

	Optional<KeystoreModel> findByAlias(String alias);

}
