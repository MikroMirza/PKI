package rs.tim33.PKI.DTO.Certificate;

import java.time.LocalDateTime;

import rs.tim33.PKI.Models.CertificateModel;

public class CertificateResponseDTO {
    public Long id;
    public String alias;           
    public String serialNumber;
    public LocalDateTime notBefore;
    public LocalDateTime notAfter;
    public Long parentId;          
    public String subjectDn;
    public String issuerDn;

    public CertificateResponseDTO(CertificateModel cert) {
        this.id = cert.getId();
        this.alias = cert.getAlias();
        this.serialNumber = cert.getSerialNumber();
        this.notBefore = cert.getNotBefore();
        this.notAfter = cert.getNotAfter();
        this.parentId = cert.getParentCertificate() != null ? cert.getParentCertificate().getId() : null;
        this.subjectDn = cert.getSubjectDn();
        this.issuerDn = cert.getIssuerDn();
    }
}