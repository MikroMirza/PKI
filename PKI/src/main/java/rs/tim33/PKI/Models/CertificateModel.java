package rs.tim33.PKI.Models;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.List;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;

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
import rs.tim33.PKI.Utils.RevocationReason;

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
    @Column(columnDefinition = "CLOB")
    private byte[] publicKey;
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
    @Column(name = "revocation_reason")
    private Integer  revocationReason;
    public RevocationReason getRevocationReason() {
        return revocationReason == null ? null : RevocationReason.fromCode(revocationReason);
    }

    public void setRevocationReason(RevocationReason reason) {
        this.revocationReason = reason != null ? reason.getCode() : null;
    }
    
    private LocalDateTime revokedAt;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "parent_certificate_id")
    private CertificateModel parentCertificate;
    @ManyToOne
    private CertificateModel rootCertificate;
    
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
        if(parent != null)
        	setRootCertificate(parent.getRootCertificate());
        else
        	setRootCertificate(this);
        
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
        setPublicKey(cert.getPublicKey().getEncoded());
    }
    
    public X509Certificate getCertificate() throws Exception {
    	CertificateFactory cf;
		try {
			cf = CertificateFactory.getInstance("X.509");
	    	X509Certificate decodedCert = (X509Certificate) cf.generateCertificate(
	    	        new ByteArrayInputStream(this.certData)
	    	        );
	    	
	    	return decodedCert;
		} catch (CertificateException e) {
			e.printStackTrace();
			throw new Exception();
		}
    }
    
    public int GetPathLenConstraint() throws Exception {
    	CertificateFactory cf;
		try {
			cf = CertificateFactory.getInstance("X.509");
	    	X509Certificate decodedCert = (X509Certificate) cf.generateCertificate(
	    	        new ByteArrayInputStream(this.certData)
	    	        );
	    	
	    	return decodedCert.getBasicConstraints();
		} catch (CertificateException e) {
			e.printStackTrace();
			throw new Exception();
		}
    }
}
