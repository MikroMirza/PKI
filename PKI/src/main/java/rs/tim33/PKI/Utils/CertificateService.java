package rs.tim33.PKI.Utils;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.sql.Date;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.List;

import javax.security.sasl.AuthenticationException;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;

import rs.tim33.PKI.DTO.Certificate.CreateCertificateDTO;
import rs.tim33.PKI.Exceptions.CertificateGenerationException;
import rs.tim33.PKI.Exceptions.InvalidCertificateRequestException;
import rs.tim33.PKI.Exceptions.InvalidIssuerException;
import rs.tim33.PKI.Exceptions.ValidateArgumentsException;
import rs.tim33.PKI.Models.CertificateModel;
import rs.tim33.PKI.Models.CertificateType;
import rs.tim33.PKI.Models.Role;
import rs.tim33.PKI.Models.UserModel;
import rs.tim33.PKI.Repositories.CertificateRepository;
import rs.tim33.PKI.Repositories.UserRepository;
import rs.tim33.PKI.Services.CRLService;
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
	
	private void validateGeneralData(
			String cn,
			String org,
			String orgUnit,
			LocalDateTime notBefore,
			LocalDateTime notAfter
			) throws AuthenticationException, InvalidCertificateRequestException {
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
	}
	
	private void validateNonSelfIssuedCertData(
			Long issuerId,
			String cn,
			String org,
			String orgUnit,
			LocalDateTime notBefore,
			LocalDateTime notAfter
			) throws AuthenticationException, InvalidIssuerException, InvalidCertificateRequestException, AccessDeniedException {
		validateGeneralData(cn, org, orgUnit, notBefore, notAfter);
		
		CertificateModel parentCert = certRepo.findById(issuerId).orElse(null);

		if(parentCert == null)
			throw new InvalidCertificateRequestException("Nonexistent issuer certificate");
		if (parentCert.isRevoked())
		    throw new InvalidIssuerException("Cannot issue a certificate: the parent certificate has been revoked.");
		if(notBefore.isBefore(parentCert.getNotBefore()))
			throw new InvalidCertificateRequestException("New certificate can't start before the issuing certificate");
		if(notAfter.isAfter(parentCert.getNotAfter()))
			throw new InvalidCertificateRequestException("New certificate can't end after the issuing certificate");
		//If the issuing certificate has expired
		if(parentCert.getNotAfter().isBefore(LocalDateTime.now()))
			throw new InvalidIssuerException("The issuing certificate has expired");
		//TODO: CHECK PARENT EXTENSIONS
		//BASIC CONSTRAINT AND STUFF
		
		//Check CA user stuff
		UserModel user = loggedUserUtils.getLoggedInUser();
		
		if(user.getRole() == Role.CA) {
			if(!user.getCACerts().contains(parentCert.getRootCertificate()))
				throw new AccessDeniedException("CA Users can only issue certificates for their organization");
		}
	}
	
	private void validateRootCertData(
			String cn, 
			String org, 
			String orgUnit, 
			LocalDateTime 
			notBefore, 
			LocalDateTime notAfter,
			int pathLenConstraint
			) throws AuthenticationException, InvalidCertificateRequestException {
		validateGeneralData(cn, org, orgUnit, notBefore, notAfter);
		if(loggedUserUtils.getLoggedInRole() != Role.ADMIN)
			throw new AccessDeniedException("Only admins can create root certificates");
		
		if (pathLenConstraint < 0)
			throw new InvalidCertificateRequestException("Path len can't be negative");
	}
	
	private void validateIntermediateCertData(
			Long issuerId,
			String cn,
			String org,
			String orgUnit,
			LocalDateTime notBefore,
			LocalDateTime notAfter,
			int pathLenConstraint
			) throws AuthenticationException, InvalidIssuerException, InvalidCertificateRequestException, AccessDeniedException {
		validateNonSelfIssuedCertData(issuerId, cn, org, orgUnit, notBefore, notAfter);
		
		if (pathLenConstraint < 0)
			throw new InvalidCertificateRequestException("Path len can't be negative");

		UserModel user = loggedUserUtils.getLoggedInUser();
		if (user.getRole() != Role.ADMIN && user.getRole() != Role.CA)
			throw new AccessDeniedException("Only Admins and CA users can issue intermediate certificates");
	}
	
	private void validateEndEntityCertData(
			Long issuerId,
			String cn,
			String org,
			String orgUnit,
			LocalDateTime notBefore,
			LocalDateTime notAfter
			) throws AuthenticationException, InvalidIssuerException, InvalidCertificateRequestException, AccessDeniedException {
		validateNonSelfIssuedCertData(issuerId, cn, org, orgUnit, notBefore, notAfter);
	}
	
	public int generateKeyUsageBits(Iterable<String> keys) {
		int bits = 0;
		for(String s : keys)
			switch(s) {
			case "digitalSignature": bits |= KeyUsage.digitalSignature; break;
			case "nonRepudiation": bits |= KeyUsage.nonRepudiation; break;
			case "keyEncipherment": bits |= KeyUsage.keyEncipherment; break;
			case "dataEncipherment": bits |= KeyUsage.dataEncipherment; break;
			case "keyAgreement": bits |= KeyUsage.keyAgreement; break;
			case "keyCertSign": bits |= KeyUsage.keyCertSign; break;
			case "cRLSign": bits |= KeyUsage.cRLSign; break;
			case "encipherOnly": bits |= KeyUsage.encipherOnly; break;
			case "decipherOnly": bits |= KeyUsage.decipherOnly; break;
			}
		return bits;
	}
	
	public KeyPairAndCert generateCertificate(CreateCertificateDTO data)
			throws AuthenticationException, InvalidCertificateRequestException, InvalidIssuerException, AccessDeniedException, CertificateGenerationException {
		if(data.certType == CertificateType.END_ENTITY)
			validateEndEntityCertData(data.issuerId, data.subject.commonName, data.subject.organization, data.subject.orgUnit, data.notBefore, data.notAfter);
		else if(data.certType == CertificateType.INTERMEDIATE)
			validateIntermediateCertData(data.issuerId, data.subject.commonName, data.subject.organization, data.subject.orgUnit, data.notBefore, data.notAfter, data.pathLenConstraint);
		else
			validateRootCertData(data.subject.commonName, data.subject.organization, data.subject.orgUnit, data.notBefore, data.notAfter, data.pathLenConstraint);
		
		//Generate keys
		KeyPairGenerator keyGen;
		try {
			keyGen = KeyPairGenerator.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			throw new CertificateGenerationException("Unsupported key generation algorithm");
		}
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        
        //Create certificate builder
		CertificateModel parentCert = certRepo.findById(data.issuerId).orElse(null);
		
		String subjectDn = "";
		if(!data.subject.commonName.isBlank()) subjectDn += "CN=" + data.subject.commonName;
		if(!data.subject.organization.isBlank()) subjectDn += ", O=" + data.subject.organization;
		if(!data.subject.orgUnit.isBlank()) subjectDn += ", OU=" + data.subject.orgUnit;
		if(!data.subject.country.isBlank()) subjectDn += ", C=" + data.subject.country;
		if(!data.subject.state.isBlank()) subjectDn += ", S=" + data.subject.state;
		if(!data.subject.locality.isBlank()) subjectDn += ", L=" + data.subject.locality;
		X500Name subject = new X500Name(subjectDn);
        X500Name issuer;
        if(parentCert != null) issuer = new X500Name(parentCert.getSubjectDn());
        else issuer = new X500Name(subjectDn);
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        
        JcaX509v3CertificateBuilder certBuilder =
                new JcaX509v3CertificateBuilder(
                        issuer,
                        serial,
                        Date.from(data.notBefore.atZone(ZoneId.systemDefault()).toInstant()),
                        Date.from(data.notAfter.atZone(ZoneId.systemDefault()).toInstant()),
                        subject,
                        keyPair.getPublic());
		
        
        
        //Extensions
        //Subject and Auth keys
        try {
            JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
			certBuilder.addExtension(Extension.subjectKeyIdentifier, false, 
					extUtils.createSubjectKeyIdentifier(keyPair.getPublic()));
			if(parentCert != null)
				certBuilder.addExtension(Extension.authorityKeyIdentifier, false,
						extUtils.createAuthorityKeyIdentifier(parentCert.getCertificate()));
		} catch (Exception e) {
			e.printStackTrace();
			throw new CertificateGenerationException("Error adding key id extensions");
		}
        
        //BasicConstraint
        BasicConstraints constraint;
        if(data.certType == CertificateType.END_ENTITY) constraint = new BasicConstraints(false);
        else constraint = new BasicConstraints(data.pathLenConstraint);
        try {
			certBuilder.addExtension(Extension.basicConstraints, true, constraint);
		} catch (CertIOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw new CertificateGenerationException("Error adding basic constraint");
		}
        
        //SAN
        GeneralName[] sanArray = data.san.stream().map(entry -> {
            int type;
            switch (entry.type.toLowerCase()) {
                case "dns": type = GeneralName.dNSName; break;
                case "email": type = GeneralName.rfc822Name; break;
                case "ip": type = GeneralName.iPAddress; break;
                case "uri": type = GeneralName.uniformResourceIdentifier; break;
                default: throw new CertificateGenerationException("Unsupported SAN type: " + entry.value);
            }
            return new GeneralName(type, entry.value);
        }).toArray(GeneralName[]::new);
        try {
			certBuilder.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(sanArray));
		} catch (CertIOException e) {
			e.printStackTrace();
			throw new CertificateGenerationException("Error adding SAN constraint");
		}
        
        //KeyUsage
        int keyUsageBits = generateKeyUsageBits(data.keyUsage);
        try {
			certBuilder.addExtension(Extension.keyUsage, false, new KeyUsage(keyUsageBits));
		} catch (CertIOException e) {
			e.printStackTrace();
			throw new CertificateGenerationException("Error adding keyusage constraint");
		}
        
        //ExtendedKeyUsage
        if (data.extendedKeyUsage != null) {
            List<KeyPurposeId> ekuList = new ArrayList<>();
            for (String eku : data.extendedKeyUsage) {
                if ("serverAuth".equals(eku)) ekuList.add(KeyPurposeId.id_kp_serverAuth);
                if ("clientAuth".equals(eku)) ekuList.add(KeyPurposeId.id_kp_clientAuth);
            }
            try {
				certBuilder.addExtension(Extension.extendedKeyUsage, false,
				        new ExtendedKeyUsage(ekuList.toArray(new KeyPurposeId[0])));
			} catch (CertIOException e) {
				e.printStackTrace();
				throw new CertificateGenerationException("Error adding EKU constraint");
			}
        }
        
        //CRL
        try {
			certBuilder.addExtension(
				    Extension.cRLDistributionPoints,
				    false,
				    new CRLDistPoint(new DistributionPoint[] {
				        new DistributionPoint(
				            new DistributionPointName(
				                new GeneralNames(
				                    new GeneralName(GeneralName.uniformResourceIdentifier,
				                        "https://localhost:8443/crl/" + data.issuerId))),
				            null,
				            null)
				    })
				);

			
		} catch (CertIOException e) {
			e.printStackTrace();
			throw new CertificateGenerationException("Error setting certificate crld constraints");
		}
        
        X509Certificate cert;
        //Create certificate
        try {
            ContentSigner signer;
            if(parentCert != null) signer = new JcaContentSignerBuilder("SHA256withRSA").build(getPrivateKeyOfCert(data.issuerId));
            else signer = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());
            
            cert = new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));
        } catch (Exception e) {
			throw new CertificateGenerationException("Error signing certificate");
		}
        
        //Persist it in the database
        CertificateModel certModel = new CertificateModel(cert, parentCert);
        try {
            byte[] privateKeyPassword = keyHelper.decryptKeystoreKey(keystoreService.getEncryptedKeyFromAlias(certModel.getAlias())).getEncoded();
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
		if(loggedUserUtils.getLoggedInRole() == Role.CA) {
			UserModel user = loggedUserUtils.getLoggedInUser();
			return certRepo.findAll().stream().filter(cert -> user.getCACerts().contains(cert.getRootCertificate())).toList();
		}
		//TODO
		if(loggedUserUtils.getLoggedInRole() == Role.USER)
			return certRepo.findAll()
					.stream()
					.filter(t -> {return (t.getOwnerUser() != null && t.getOwnerUser().getEmail().equals(loggedUserUtils.getLoggedInUser().getEmail()));}).toList();
		
		return new ArrayList<CertificateModel>();
	}
	
	public void revokeCertificate(CertificateModel cert, String reason) {
		if(cert.isRevoked())
			return;
		
		cert.setRevoked(true);
		cert.setRevocationReason(reason);
		cert.setRevokedAt(LocalDateTime.now());
		
		//Maybe disable private key.
		
		List<CertificateModel> children = cert.getChildCertificates();
		for(CertificateModel child: children) {
			revokeCertificate(child,"Parent certificate: " + cert.getAlias() + " has been revoked.");
		}
		
		//TODO: Save crl to file in generate, and call generate from here - low priority who cares
	}
	
}