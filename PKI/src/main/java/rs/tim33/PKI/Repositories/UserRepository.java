package rs.tim33.PKI.Repositories;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import rs.tim33.PKI.Models.KeystoreModel;
import rs.tim33.PKI.Models.UserModel;

@Repository
public interface UserRepository extends JpaRepository<UserModel, Long>{

	Optional<UserModel> findByEmail(String email);
}
