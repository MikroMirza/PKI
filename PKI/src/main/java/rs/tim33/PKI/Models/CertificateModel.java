package rs.tim33.PKI.Models;

import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.List;

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

	//Private key keystore (if it exists)
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "keystore_id")
    private KeystoreModel keystore;

    private String alias;
    
    //X500Name
    @Column(columnDefinition = "TEXT")
    private String subjectDn;
    @Column(columnDefinition = "TEXT")
    private String issuerDn;
    
    private String serialNumber;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "parent_certificate_id")
    private CertificateModel parentCertificate;

    private LocalDateTime notBefore;
    private LocalDateTime notAfter;

    //X509Certificate serialized
    @Lob
    private byte[] certData; 

    //Revoke stuff
    private boolean revoked = false;
    private String revocationReason;
    private LocalDateTime revokedAt;

    private LocalDateTime createdAt = LocalDateTime.now();
    private LocalDateTime updatedAt = LocalDateTime.now();

    @OneToMany(mappedBy = "parentCertificate")
    private List<CertificateModel> childCertificates;
    
    @ManyToOne
    private UserModel ownerUser;
    
    public CertificateModel() {}
    
    public CertificateModel(X509Certificate cert, KeystoreModel keystore, CertificateModel parent) {
    	setKeystore(keystore);
        setAlias(cert.getSubjectX500Principal().getName());
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

        setCreatedAt(LocalDateTime.now());
        setUpdatedAt(LocalDateTime.now());
    }
}
