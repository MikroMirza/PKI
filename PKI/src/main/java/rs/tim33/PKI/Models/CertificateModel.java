package rs.tim33.PKI.Models;

import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.List;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Lob;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import lombok.Getter;
import lombok.Setter;

@Entity
@Getter
@Setter
@Table(uniqueConstraints = @UniqueConstraint(columnNames = {"alias", "serialNumber"}))
public class CertificateModel {
	@Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String alias;
    private String serialNumber;
    private LocalDateTime notBefore;
    private LocalDateTime notAfter;
    private String organization;
    @Lob
    private byte[] encryptedPrivateKey;
    
    //X500Name
    @Column(columnDefinition = "TEXT")
    private String subjectDn;
    @Column(columnDefinition = "TEXT")
    private String issuerDn;
    

    //X509Certificate serialized
    @Lob
    private byte[] certData; 

    //Revoke stuff
    private boolean revoked = false;
    private String revocationReason;
    private LocalDateTime revokedAt;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "parent_certificate_id")
    private CertificateModel parentCertificate;
    
    @OneToMany(mappedBy = "parentCertificate")
    private List<CertificateModel> childCertificates;
    
    @ManyToOne
    private UserModel ownerUser;
    
    public CertificateModel() {}
    
    public CertificateModel(X509Certificate cert, CertificateModel parent, String keyAlias) {
        setAlias(keyAlias);
        setSubjectDn(cert.getSubjectX500Principal().getName());
        setIssuerDn(cert.getIssuerX500Principal().getName());
        setSerialNumber(cert.getSerialNumber().toString());
        
        setParentCertificate(parent);
		setNotBefore(LocalDateTime.ofInstant(cert.getNotBefore().toInstant(), ZoneId.systemDefault()));
		setNotAfter(LocalDateTime.ofInstant(cert.getNotAfter().toInstant(), ZoneId.systemDefault()));

        try {
            setCertData(cert.getEncoded());
        } catch (Exception e) {
            throw new RuntimeException("Failed to encode X509Certificate", e);
        }

        setRevoked(false);
        setRevocationReason(null);
        setRevokedAt(null);

        X500Name name = new X500Name(cert.getSubjectX500Principal().getName());
        setOrganization(name.getRDNs(BCStyle.O)[0].getFirst().getValue().toString());
    }
}
