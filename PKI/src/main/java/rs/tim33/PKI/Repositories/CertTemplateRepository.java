package rs.tim33.PKI.Repositories;

import org.springframework.data.jpa.repository.JpaRepository;

import rs.tim33.PKI.Models.CertificateTemplate;

public interface CertTemplateRepository extends JpaRepository<CertificateTemplate, Long>{

}
