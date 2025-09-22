package rs.tim33.PKI.Utils;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.sql.Date;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

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
	
	public KeyPairAndCert createIntermediate(Long parentCertId, String org, String orgUnit, int daysValid) throws Exception {
		CertificateModel parentCert = certRepo.findById(parentCertId).orElse(null);
		
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
		
		long now = System.currentTimeMillis();
        Date startDate = new Date(now);
        Date endDate = new Date(now + daysValid * 24L * 60 * 60 * 1000);
        
        X500Name subject = new X500Name("CN=Intermediate, O=" + org + ", OU=" + orgUnit);
        X500Name issuer = new X500Name(parentCert.getSubjectDn());
        BigInteger serial = BigInteger.valueOf(now);
        
        JcaX509v3CertificateBuilder certBuilder =
                new JcaX509v3CertificateBuilder(
                        issuer, serial, startDate, endDate, subject, keyPair.getPublic());
		
        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        
        //Create certificate
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(getPrivateKeyOfCert(parentCertId));
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));
        
        //Persist it in the database
        CertificateModel certModel = new CertificateModel(cert, parentCert, org);
        byte[] privateKeyPassword = keyHelper.decryptKeystoreKey(keystoreService.getEncryptedKeyFromAlias(org)).getEncoded();
        byte[] encryptedPrivateKey = keyHelper.encryptPrivateKey(keyPair.getPrivate(), privateKeyPassword);
        certModel.setEncryptedPrivateKey(encryptedPrivateKey);
        
        certRepo.save(certModel);
        
		return new KeyPairAndCert(keyPair, cert);
	}
	
	public KeyPairAndCert createEndEntity(Long parentCertId, Long endUserId, String certName, int daysValid) throws Exception {
		CertificateModel parentCert = certRepo.findById(parentCertId).orElse(null);
		UserModel user = userRepo.findById(endUserId).orElse(null);
		
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
		
		long now = System.currentTimeMillis();
        Date startDate = new Date(now);
        Date endDate = new Date(now + daysValid * 24L * 60 * 60 * 1000);
        
        X500Name subject = new X500Name("CN="+user.getName() + certName + ", O="+user.getOrganization());
        X500Name issuer = new X500Name(parentCert.getSubjectDn());
        BigInteger serial = BigInteger.valueOf(now);
        
        JcaX509v3CertificateBuilder certBuilder =
                new JcaX509v3CertificateBuilder(
                        issuer, serial, startDate, endDate, subject, keyPair.getPublic());
		
        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        
        //Create certificate
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(getPrivateKeyOfCert(parentCertId));
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));
        
        //Persist it in the database
        CertificateModel certModel = new CertificateModel(cert, parentCert, user.getOrganization());
        byte[] privateKeyPassword = keyHelper.decryptKeystoreKey(keystoreService.getEncryptedKeyFromAlias(user.getOrganization())).getEncoded();
        byte[] encryptedPrivateKey = keyHelper.encryptPrivateKey(keyPair.getPrivate(), privateKeyPassword);
        certModel.setEncryptedPrivateKey(encryptedPrivateKey);
        
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