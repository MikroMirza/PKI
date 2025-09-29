package rs.tim33.PKI.Repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import rs.tim33.PKI.Models.GenerateCertificateRequest;

@Repository
public interface RequestCertificateRepository extends JpaRepository<GenerateCertificateRequest, Long>{

}
