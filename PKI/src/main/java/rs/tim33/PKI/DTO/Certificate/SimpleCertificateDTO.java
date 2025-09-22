package rs.tim33.PKI.DTO.Certificate;

import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.util.Base64;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;

import com.fasterxml.jackson.annotation.JsonFormat;

import rs.tim33.PKI.Models.CertificateModel;

public class SimpleCertificateDTO {
	public Long id;
	public String subjectCN;
	public String subjectO;
	public String subjectOU;
	public String issuerCN;
	public String issuerO;
	public String issuerOU;
	public String publicKey;

    @JsonFormat(pattern = "yyyy-MM-dd'T'HH:mm:ss")
    private LocalDateTime notBefore;
    @JsonFormat(pattern = "yyyy-MM-dd'T'HH:mm:ss")
    private LocalDateTime notAfter;
    
    public SimpleCertificateDTO(CertificateModel cert) {
    	id = cert.getId();
    	
    	X500Name subjectName = new X500Name(cert.getSubjectDn());
    	if (subjectName.getRDNs(BCStyle.CN).length > 0)
    		this.subjectCN = subjectName.getRDNs(BCStyle.CN)[0].getFirst().getValue().toString();
    	if (subjectName.getRDNs(BCStyle.O).length > 0)
    		this.subjectO = subjectName.getRDNs(BCStyle.O)[0].getFirst().getValue().toString();
    	if (subjectName.getRDNs(BCStyle.OU).length > 0)
    		this.subjectOU = subjectName.getRDNs(BCStyle.OU)[0].getFirst().getValue().toString();

    	X500Name issuerName = new X500Name(cert.getIssuerDn());
    	if (issuerName.getRDNs(BCStyle.CN).length > 0)
    		this.issuerCN = issuerName.getRDNs(BCStyle.CN)[0].getFirst().getValue().toString();
    	if (issuerName.getRDNs(BCStyle.O).length > 0)
    		this.issuerO = issuerName.getRDNs(BCStyle.O)[0].getFirst().getValue().toString();
    	if (issuerName.getRDNs(BCStyle.OU).length > 0)
    		this.issuerOU = issuerName.getRDNs(BCStyle.OU)[0].getFirst().getValue().toString();

    	publicKey = Base64.getEncoder().encodeToString(cert.getPublicKey());
    	notBefore = cert.getNotBefore();
    	notAfter = cert.getNotAfter();
    }
}
