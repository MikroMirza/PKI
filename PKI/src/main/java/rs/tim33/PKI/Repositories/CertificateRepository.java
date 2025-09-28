package rs.tim33.PKI.Repositories;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import rs.tim33.PKI.Models.CertificateModel;

@Repository
public interface CertificateRepository extends JpaRepository<CertificateModel, Long>{
	List<CertificateModel> findByParentCertificateAndRevokedTrue(CertificateModel issuer);

}
