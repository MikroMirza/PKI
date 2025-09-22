package rs.tim33.PKI.Utils;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.sql.Date;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.List;

import javax.security.sasl.AuthenticationException;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;

import rs.tim33.PKI.Exceptions.CertificateGenerationException;
import rs.tim33.PKI.Exceptions.InvalidCertificateRequestException;
import rs.tim33.PKI.Exceptions.InvalidIssuerException;
import rs.tim33.PKI.Models.CertificateModel;
import rs.tim33.PKI.Models.Role;
import rs.tim33.PKI.Models.UserModel;
import rs.tim33.PKI.Repositories.CertificateRepository;
import rs.tim33.PKI.Repositories.UserRepository;
import rs.tim33.PKI.Services.KeystoreService;

@Service
public class CertificateService {
	
	public static class KeyPairAndCert {
        private final KeyPair keyPair;
        private final X509Certificate certificate;

        public KeyPairAndCert(KeyPair keyPair, X509Certificate certificate) {
            this.keyPair = keyPair;
            this.certificate = certificate;
        }
        public KeyPair getKeyPair() { return keyPair; }
        public X509Certificate getCertificate() { return certificate; }
    }

	@Autowired
	private CertificateRepository certRepo;
	@Autowired 
	private UserRepository userRepo;
	
	@Autowired
	private KeystoreService keystoreService;
	
	@Autowired
	private KeyHelper keyHelper;
	@Autowired
	private LoggedUserUtils loggedUserUtils;
	
	public PrivateKey getPrivateKeyOfCert(Long certificateId) throws Exception {
		CertificateModel cert = certRepo.findById(certificateId).orElse(null);
		
		byte[] keystoreKey = keyHelper.decryptKeystoreKey(keystoreService.getEncryptedKeyFromAlias(cert.getAlias())).getEncoded();
		PrivateKey privateKey = keyHelper.decryptPrivateKey(cert.getEncryptedPrivateKey(), keystoreKey);
		return privateKey;
	}
	
	public KeyPairAndCert createSelfSigned(String dn, int daysValid) throws Exception {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();

        long now = System.currentTimeMillis();
        Date startDate = new Date(now);
        Date endDate = new Date(now + daysValid * 24L * 60 * 60 * 1000);

        X500Name issuer = new X500Name(dn);
        BigInteger serial = BigInteger.valueOf(now);

        JcaX509v3CertificateBuilder certBuilder =
                new JcaX509v3CertificateBuilder(
                        issuer, serial, startDate, endDate, issuer, keyPair.getPublic());

        //CA=true so the org can create new certificates
        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));
        
        //TODO ENCRYPT STUFF
        CertificateModel certModel = new CertificateModel(cert, null, "Root");
        byte[] privateKeyPassword = keyHelper.decryptKeystoreKey(keystoreService.getEncryptedKeyFromAlias("Root")).getEncoded();
        byte[] encryptedPrivateKey = keyHelper.encryptPrivateKey(keyPair.getPrivate(), privateKeyPassword);
        certModel.setEncryptedPrivateKey(encryptedPrivateKey);
        
        certRepo.save(certModel);
        
        return new KeyPairAndCert(keyPair, cert);
	}
	
	public KeyPairAndCert createCertificate(
			Long parentCertId,
			String cn,
			String org,
			String orgUnit,
			LocalDateTime notBefore,
			LocalDateTime notAfter,
			int pathLenConstraint,
			boolean isEndEntity
			) throws AuthenticationException, InvalidCertificateRequestException, InvalidIssuerException, AccessDeniedException {
		UserModel user = loggedUserUtils.getLoggedInUser();
		if(user == null)
			throw new AuthenticationException();
		
		if(cn == null || cn.length() < 3)
			throw new InvalidCertificateRequestException("Invalid common name");
		if(org == null || org.length() < 3)
			throw new InvalidCertificateRequestException("Invalid organization name");
		if(orgUnit == null || orgUnit.length() < 3)
			throw new InvalidCertificateRequestException("Invalid organization unit");
		if(notBefore == null)
			throw new InvalidCertificateRequestException("Invalid notBefore time");
		if(notAfter == null)
			throw new InvalidCertificateRequestException("Invalid notAfter time");
			
		if(notBefore.isAfter(notAfter))
			throw new InvalidCertificateRequestException("NotBefore must be before NotAfter");	
		
		
		CertificateModel parentCert = certRepo.findById(parentCertId).orElse(null);
		if(parentCert == null)
			throw new InvalidCertificateRequestException("Nonexistent issuer certificate");
		if(notBefore.isBefore(parentCert.getNotBefore()))
			throw new InvalidCertificateRequestException("New certificate can't start before the issuing certificate");
		if(notAfter.isAfter(parentCert.getNotAfter()))
			throw new InvalidCertificateRequestException("New certificate can't end after the issuing certificate");
		//If the issuing certificate has expired
		if(parentCert.getNotAfter().isBefore(LocalDateTime.now()))
			throw new InvalidIssuerException("The issuing certificate has expired");
			
		//Check path len
		try {
			if(!isEndEntity && pathLenConstraint >= parentCert.GetPathLenConstraint())
				throw new InvalidIssuerException("Path len MUST be smaller than the issuing certificate path len");
			if(parentCert.GetPathLenConstraint() == -1)
				throw new InvalidIssuerException("Issuing certificate can't be an end-entity certificate");
		} catch (InvalidIssuerException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw e;
		} catch (Exception e) {
			e.printStackTrace();
			throw new InvalidCertificateRequestException("");
		}
		
		//Check CA user stuff
		if(user.getRole() == Role.CA) {
			if(!org.equals(user.getOrganization()))
				throw new AccessDeniedException("CA Users can only issue certificates for their organization");
			
			if(!parentCert.getOrganization().equals(user.getOrganization()))
				throw new AccessDeniedException("CA Users can only issue certificates for their organization");
		}
		
		//Check CA certificate stuff
		if(!isEndEntity) {
			if (pathLenConstraint < 0)
				throw new InvalidCertificateRequestException("Path len can't be negative");
			
			if (user.getRole() != Role.ADMIN && user.getRole() != Role.CA)
				throw new AccessDeniedException("Only CA users can issue CA certificates");
		}
		
		KeyPairGenerator keyGen;
		try {
			keyGen = KeyPairGenerator.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			throw new CertificateGenerationException("Unsupported key generation algorithm");
		}
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        
        X500Name subject = new X500Name("CN=" + cn + ", O=" + org + ", OU=" + orgUnit);
        X500Name issuer = new X500Name(parentCert.getSubjectDn());
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        
        JcaX509v3CertificateBuilder certBuilder =
                new JcaX509v3CertificateBuilder(
                        issuer,
                        serial,
                        Date.from(notBefore.atZone(ZoneId.systemDefault()).toInstant()),
                        Date.from(notAfter.atZone(ZoneId.systemDefault()).toInstant()),
                        subject,
                        keyPair.getPublic());
		
        BasicConstraints constraint;
        if(isEndEntity)
        	constraint = new BasicConstraints(false);
        else
        	constraint = new BasicConstraints(pathLenConstraint);
        
        try {
			certBuilder.addExtension(Extension.basicConstraints, true, constraint);
		} catch (CertIOException e) {
			e.printStackTrace();
			throw new CertificateGenerationException("Error setting certificate basic constraints");
		}
        
        X509Certificate cert;
        //Create certificate
        try {
            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(getPrivateKeyOfCert(parentCertId));
            cert = new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));
        } catch (Exception e) {
			throw new CertificateGenerationException("Error signing certificate");
		}
        
        //Persist it in the database
        CertificateModel certModel = new CertificateModel(cert, parentCert, org);
        try {
            byte[] privateKeyPassword = keyHelper.decryptKeystoreKey(keystoreService.getEncryptedKeyFromAlias(org)).getEncoded();
            byte[] encryptedPrivateKey = keyHelper.encryptPrivateKey(keyPair.getPrivate(), privateKeyPassword);
            certModel.setEncryptedPrivateKey(encryptedPrivateKey);
        } catch (Exception e) {
        	throw new CertificateGenerationException("Error encrypting private key");
		}
        
        certRepo.save(certModel);
        
		return new KeyPairAndCert(keyPair, cert);
	}
	
	public List<CertificateModel> getAllCertificates() {
		if(loggedUserUtils.getLoggedInRole() == Role.ADMIN)
			return certRepo.findAll();
		if(loggedUserUtils.getLoggedInRole() == Role.CA)
			return certRepo.findByOrganization(loggedUserUtils.getLoggedInOrganization());
		if(loggedUserUtils.getLoggedInRole() == Role.ADMIN)
			return certRepo.findAll()
					.stream()
					.filter(t -> {return (t.getOwnerUser() != null && t.getOwnerUser().getEmail().equals(loggedUserUtils.getLoggedInUser().getEmail()));}).toList();
		
		return new ArrayList<CertificateModel>();
	}
}