package rs.tim33.PKI.Utils;

import java.io.ByteArrayInputStream;
import java.io.StringReader;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.sql.Date;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.sasl.AuthenticationException;

import org.apache.coyote.BadRequestException;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;

import jakarta.persistence.EntityNotFoundException;
import jakarta.transaction.Transactional;
import rs.tim33.PKI.DTO.Certificate.CreateCertificateDTO;
import rs.tim33.PKI.DTO.Certificate.GenerateCertificateRequestDTO;
import rs.tim33.PKI.DTO.Certificate.SubjectDTO;
import rs.tim33.PKI.Exceptions.CertificateGenerationException;
import rs.tim33.PKI.Exceptions.InvalidCertificateRequestException;
import rs.tim33.PKI.Exceptions.InvalidIssuerException;
import rs.tim33.PKI.Exceptions.ValidateArgumentsException;
import rs.tim33.PKI.Models.CertificateModel;
import rs.tim33.PKI.Models.CertificateTemplate;
import rs.tim33.PKI.Models.CertificateType;
import rs.tim33.PKI.Models.GenerateCertificateRequest;
import rs.tim33.PKI.Models.Role;
import rs.tim33.PKI.Models.UserModel;
import rs.tim33.PKI.Repositories.CertTemplateRepository;
import rs.tim33.PKI.Repositories.CertificateRepository;
import rs.tim33.PKI.Repositories.RequestCertificateRepository;
import rs.tim33.PKI.Repositories.UserRepository;
import rs.tim33.PKI.Services.CRLService;
import rs.tim33.PKI.Services.KeystoreService;
import rs.tim33.PKI.Services.TemplateService;
import rs.tim33.PKI.Utils.CertificateService.KeyPairAndCert;

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
	private LoggedUserUtils utils;
	@Autowired
	private CertificateRepository certRepo;
	@Autowired 
	private UserRepository userRepo;
	@Autowired 
	private RequestCertificateRepository reqRepo;
	@Autowired
	private CertTemplateRepository templateRepo;
	
	@Autowired
	private KeystoreService keystoreService;
	
	@Autowired
	private KeyHelper keyHelper;
	@Autowired
	private LoggedUserUtils loggedUserUtils;
	
	public PrivateKey getPrivateKeyOfCert(Long certificateId) throws Exception {
		CertificateModel cert = certRepo.findById(certificateId).orElse(null);
		
		String orgEncrypted = keystoreService.getEncryptedKeyFromAlias(cert.getAlias());
		byte[] orgDecrypted = keyHelper.decrypt(keyHelper.getMasterKey(), orgEncrypted);
		SecretKey orgKey = new SecretKeySpec(orgDecrypted, "AES");
		String privateEncrypted = cert.getEncryptedPrivateKey();
		byte[] privateDecrypted = keyHelper.decrypt(orgKey, privateEncrypted);
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateDecrypted);
		PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(keySpec);

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
		if(notBefore == null)
			throw new InvalidCertificateRequestException("Invalid notBefore time");
		if(notAfter == null)
			throw new InvalidCertificateRequestException("Invalid notAfter time");
			
		if(notBefore.isAfter(notAfter))
			throw new InvalidCertificateRequestException("NotBefore must be before NotAfter");	
	}
	
	private void validateTemplateData(Long templateId, CreateCertificateDTO data) throws BadRequestException, EntityNotFoundException {
		CertificateTemplate temp = templateRepo.findById(templateId).orElseThrow(() -> new EntityNotFoundException("Template not found"));
		CertificateModel issuer = temp.getTemplateOwner();
		
		if(data.issuerId != issuer.getId())
			throw new BadRequestException("Template not available");
		
		//CN
		if(temp.getCnRegex() != null && !temp.getCnRegex().isBlank() && !data.subject.commonName.matches(temp.getCnRegex()))
			throw new BadRequestException("The given common name doesn't fit the template");
		
		//SAN
		//invalid types
		if(data.san.stream().anyMatch(t -> !temp.getAllowedTypes().contains(t.type.toLowerCase())))
			throw new BadRequestException("The given SAN types don't fit the template");
		
		//missing types
		for(String type : temp.getAllowedTypes())
			if (data.san.stream().noneMatch(t -> t.type.toLowerCase().equals(type)))
				throw new BadRequestException("Missing required SAN");
		
		//regex
		//dns
		if(temp.getAllowedTypes().contains("dns") &&
			!temp.getDnsRegex().isBlank() &&
			data.san.stream().filter(t -> t.type.toLowerCase().equals("dns")).anyMatch(t -> !t.value.matches(temp.getDnsRegex())))
			throw new BadRequestException("The given SAN dns doesn't fit the template");

		//ip
		if(temp.getAllowedTypes().contains("ip") &&
			!temp.getIpRegex().isBlank() &&
			data.san.stream().filter(t -> t.type.toLowerCase().equals("ip")).anyMatch(t -> !t.value.matches(temp.getIpRegex())))
			throw new BadRequestException("The given SAN ip doesn't fit the template");

		//email
		if(temp.getAllowedTypes().contains("email") &&
			!temp.getEmailRegex().isBlank() &&
			data.san.stream().filter(t -> t.type.toLowerCase().equals("email")).anyMatch(t -> !t.value.matches(temp.getEmailRegex())))
			throw new BadRequestException("The given SAN email doesn't fit the template");

		//uri
		if(temp.getAllowedTypes().contains("uri") &&
			!temp.getUriRegex().isBlank() &&
			data.san.stream().filter(t -> t.type.toLowerCase().equals("uri")).anyMatch(t -> !t.value.matches(temp.getUriRegex())))
			throw new BadRequestException("The given SAN uri doesn't fit the template");
		
	}
	
	private void validateNonSelfIssuedCertData(
			Long issuerId,
			String cn,
			String org,
			String orgUnit,
			LocalDateTime notBefore,
			LocalDateTime notAfter,
			int pathLenConstraint
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
		
		UserModel user = loggedUserUtils.getLoggedInUser();
		if(user != null && user.getRole() == Role.CA) {
			if(!getUsersCertificates(user).contains(parentCert))
				throw new InvalidCertificateRequestException("Certificate is unavailable for this user");
		}
		
		if(pathLenConstraint >= parentCert.getPathLenConstraint())
			throw new InvalidCertificateRequestException("Path len must be lower than the issuing certificate's");
		
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
		validateNonSelfIssuedCertData(issuerId, cn, org, orgUnit, notBefore, notAfter, pathLenConstraint);
		
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
		validateNonSelfIssuedCertData(issuerId, cn, org, orgUnit, notBefore, notAfter, -1);
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
	
	@Transactional
	public KeyPairAndCert generateCertificate(CreateCertificateDTO data)
			throws AuthenticationException, InvalidCertificateRequestException, InvalidIssuerException, AccessDeniedException, CertificateGenerationException {
		if(data.certType == CertificateType.END_ENTITY)
			validateEndEntityCertData(data.issuerId, data.subject.commonName, data.subject.organization, data.subject.orgUnit, data.notBefore, data.notAfter);
		else if(data.certType == CertificateType.INTERMEDIATE)
			validateIntermediateCertData(data.issuerId, data.subject.commonName, data.subject.organization, data.subject.orgUnit, data.notBefore, data.notAfter, data.pathLenConstraint);
		else
			validateRootCertData(data.subject.commonName, data.subject.organization, data.subject.orgUnit, data.notBefore, data.notAfter, data.pathLenConstraint);
		
		if(data.templateId != 0)
			try {
				validateTemplateData(data.templateId, data);
			} catch (EntityNotFoundException | BadRequestException e) {
				throw new CertificateGenerationException(e.getMessage(), "BAD_REQUEST");
			}
		
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
		if(data.subject.commonName != null && !data.subject.commonName.isBlank()) subjectDn += "CN=" + data.subject.commonName;
		if(data.subject.organization != null && !data.subject.organization.isBlank()) subjectDn += ", O=" + data.subject.organization;
		if(data.subject.orgUnit != null && !data.subject.orgUnit.isBlank()) subjectDn += ", OU=" + data.subject.orgUnit;
		if(data.subject.country != null && !data.subject.country.isBlank()) subjectDn += ", C=" + data.subject.country;
		if(data.subject.locality != null && !data.subject.locality.isBlank()) subjectDn += ", L=" + data.subject.locality;
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

        CertificateModel certModel = certRepo.save(new CertificateModel());
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
				                        "https://localhost:8443/crl/" + certModel.getId()))),
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
        certModel.setValues(cert, parentCert);
        try {
        	String orgEncrypted = keystoreService.getEncryptedKeyFromAlias(certModel.getAlias());
    		byte[] orgDecrypted = keyHelper.decrypt(keyHelper.getMasterKey(), orgEncrypted);
    		SecretKey orgKey = new SecretKeySpec(orgDecrypted, "AES");
    		String privateEncrypted = keyHelper.encrypt(orgKey, keyPair.getPrivate().getEncoded());
    		certModel.setEncryptedPrivateKey(privateEncrypted);
        } catch (Exception e) {
        	throw new CertificateGenerationException("Error encrypting private key");
		}
        
        certRepo.save(certModel);
        
        //private key encryption / decryption test kinda
        Boolean verified = false;
        try {
        	if(parentCert != null)cert.verify(parentCert.getCertificate().getPublicKey());
        	verified = true;
        } catch (Exception e) {
        	
        }
        System.out.println("VERIFIED: " + Boolean.toString(verified));
        
		return new KeyPairAndCert(keyPair, cert);
	}
	
	public List<CertificateModel> getUsersCertificates(UserModel user){
		if(user.getRole() == Role.ADMIN)
			return certRepo.findAll();
		
		Set<CertificateModel> availableCerts = new HashSet<>();
		List<CertificateModel> certs = new ArrayList<CertificateModel>(user.getCertificates());
		while(certs.size() > 0) {
			CertificateModel cert = certs.remove(0);
			certs.addAll(cert.getChildCertificates());
			availableCerts.add(cert);
		}
		
		return availableCerts.stream().toList();
	}
	
	//Returns the certificates available to the logged in user
		public List<CertificateModel> getAllCertificates() {
			if(loggedUserUtils.getLoggedInRole() == Role.ADMIN)
				return certRepo.findAll();
			if(loggedUserUtils.getLoggedInRole() == Role.CA) {
				return getUsersCertificates(loggedUserUtils.getLoggedInUser());
			}
			if(loggedUserUtils.getLoggedInRole() == Role.USER) {
				return getUsersCertificates(loggedUserUtils.getLoggedInUser());
			}
			
			return new ArrayList<CertificateModel>();
		}
	
	//Returns the certificates available to the logged in user
	public List<CertificateModel> getAvailableCertificates() {
		if(loggedUserUtils.getLoggedInRole() == Role.ADMIN)
			return certRepo.findAll().stream().filter(cert -> !cert.isRevoked()).toList();
		if(loggedUserUtils.getLoggedInRole() == Role.CA) {
			return getUsersCertificates(loggedUserUtils.getLoggedInUser()).stream().filter(cert -> !cert.isRevoked()).toList();
		}
		if(loggedUserUtils.getLoggedInRole() == Role.USER) {
			return getUsersCertificates(loggedUserUtils.getLoggedInUser()).stream().filter(cert -> !cert.isRevoked()).toList();
		}
		
		return new ArrayList<CertificateModel>();
	}

	//Returns the CA certificates available to the logged in user
	public List<CertificateModel> getAvailableCACertificates() {
		if(loggedUserUtils.getLoggedInRole() == Role.ADMIN)
			return certRepo.findAll().stream().filter(cert -> cert.getPathLenConstraint() != -1).filter(cert -> !cert.isRevoked()).toList();
		if(loggedUserUtils.getLoggedInRole() == Role.CA) {
			return getUsersCertificates(loggedUserUtils.getLoggedInUser()).stream().filter(cert -> cert.getPathLenConstraint() != -1).filter(cert -> !cert.isRevoked()).toList();
		}
		if(loggedUserUtils.getLoggedInRole() == Role.USER) {
			return certRepo.findAll().stream().filter(cert -> cert.getPathLenConstraint() != -1).filter(cert -> !cert.isRevoked()).toList();
		}
		
		return new ArrayList<CertificateModel>();
	}
	
	@Transactional
	public CertificateModel generateCertificateFromCsr(String csrPem, Long issuerCertId, LocalDate notBefore, LocalDate notAfter) 
	        throws Exception {
		if(loggedUserUtils.getLoggedInRole() != Role.USER)
	        throw new AccessDeniedException("Only Users can create requests");
	    
	    PemReader pemReader = new PemReader(new StringReader(csrPem));
	    PemObject pemObject = pemReader.readPemObject();
	    PKCS10CertificationRequest csr = new PKCS10CertificationRequest(pemObject.getContent());

	    X500Name subject = csr.getSubject();
	    SubjectPublicKeyInfo pkInfo = csr.getSubjectPublicKeyInfo();
	    PublicKey publicKey = new JcaPEMKeyConverter().getPublicKey(pkInfo);

	    CertificateModel issuer = certRepo.findById(issuerCertId)
	            .orElseThrow(() -> new IllegalArgumentException("Issuer not found"));

	    X509Certificate certificate = generateFromCSR(
	            csr, publicKey, subject, issuer, notBefore, notAfter
	    );

	    CertificateModel certModel = new CertificateModel(certificate, issuer, subject.toString());
	    certModel = certRepo.save(certModel);
	    
	    UserModel user = loggedUserUtils.getLoggedInUser();
	    user.getCertificates().add(certModel);
	    userRepo.save(user);

	    return certRepo.save(certModel);
	}
	
	private X509Certificate generateFromCSR(
	        PKCS10CertificationRequest csr,
	        PublicKey publicKey,
	        X500Name subject,
	        CertificateModel issuer,
	        LocalDate notBefore,
	        LocalDate notAfter
	) throws Exception {
	    BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());

	    JcaX509v3CertificateBuilder certBuilder =
	            new JcaX509v3CertificateBuilder(
	                    new X500Name(issuer.getSubjectDn()),
	                    serial,
	                    Date.from(notBefore.atStartOfDay(ZoneId.systemDefault()).toInstant()),
	                    Date.from(notAfter.atStartOfDay(ZoneId.systemDefault()).toInstant()),
	                    subject,
	                    publicKey
	            );

	    Attribute[] attrs = csr.getAttributes();
	    for (Attribute attr : attrs) {
	        if (attr.getAttrType().equals(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest)) {
	            Extensions requestedExtensions = Extensions.getInstance(attr.getAttrValues().getObjectAt(0));
	            for (ASN1ObjectIdentifier oid : requestedExtensions.getExtensionOIDs()) {
	                Extension ext = requestedExtensions.getExtension(oid);
	                certBuilder.addExtension(oid, ext.isCritical(), ext.getParsedValue());
	            }
	        }
	    }
	    JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
	    certBuilder.addExtension(Extension.subjectKeyIdentifier, false,
	            extUtils.createSubjectKeyIdentifier(publicKey));
	    certBuilder.addExtension(Extension.authorityKeyIdentifier, false,
	            extUtils.createAuthorityKeyIdentifier(issuer.getCertificate()));

	    ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
	            .build(getPrivateKeyOfCert(issuer.getId()));

	    return new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));
	}


	
	@Transactional
	public CertificateModel generateCertificateFromRequest(GenerateCertificateRequestDTO dto)
	        throws AuthenticationException, InvalidCertificateRequestException,
	               InvalidIssuerException, AccessDeniedException, CertificateGenerationException {

	    if (loggedUserUtils.getLoggedInRole() != Role.USER)
	        throw new AccessDeniedException("Only Users can create requests");

	    UserModel user = utils.getLoggedInUser();
	    if (!user.getEmail().equals(dto.getEmail())) {
	        throw new ValidateArgumentsException("The email must match with your email", "USER_BAD_INPUT_EMAIL");    
	    }

	    CreateCertificateDTO createDto = new CreateCertificateDTO();
	    createDto.issuerId = dto.getIssuerCertId();
	    createDto.notBefore = dto.getNotBefore();
	    createDto.notAfter = dto.getNotAfter();
	    createDto.pathLenConstraint = 0;
	    createDto.certType = CertificateType.END_ENTITY;

	    createDto.subject = new SubjectDTO();
	    createDto.subject.commonName = dto.getCommonName();
	    createDto.subject.organization = dto.getOrganization();
	    createDto.subject.orgUnit = dto.getOrganizationalUnit();
	    createDto.subject.country = dto.getCountry();
	    createDto.subject.email = dto.getEmail();

	    createDto.san = new ArrayList<>();
	    createDto.keyUsage = new ArrayList<>();
	    createDto.extendedKeyUsage = new ArrayList<>();

	    KeyPairAndCert kpAndCert = generateCertificate(createDto);

	    CertificateModel issuer = certRepo.findById(dto.getIssuerCertId())
	            .orElseThrow(() -> new IllegalArgumentException("Issuer not found"));

	    CertificateModel certModel = new CertificateModel(kpAndCert.getCertificate(), issuer, dto.getOrganization());

	    try {
	        String orgEncrypted = keystoreService.getEncryptedKeyFromAlias(certModel.getAlias());
	        byte[] orgDecrypted = keyHelper.decrypt(keyHelper.getMasterKey(), orgEncrypted);
	        SecretKey orgKey = new SecretKeySpec(orgDecrypted, "AES");
	        String privateEncrypted = keyHelper.encrypt(orgKey, kpAndCert.getKeyPair().getPrivate().getEncoded());
	        certModel.setEncryptedPrivateKey(privateEncrypted);
	    } catch (Exception e) {
	        throw new CertificateGenerationException("Error encrypting private key");
	    }

	    certModel = certRepo.save(certModel);
	    user.getCertificates().add(certModel);
	    userRepo.save(user);
	    
	    return certRepo.save(certModel);
	}




	
	
	public void revokeCertificate(CertificateModel cert, RevocationReason reason) {
	    if (cert.isRevoked())
	        return;
	    UserModel user = loggedUserUtils.getLoggedInUser();
//	    if(user.getRole() == Role.USER)
//	        throw new AccessDeniedException("Users cannot revoke the certificates");
//	    if(checkIssuer(user, cert) && user.getRole()==Role.CA)
//	    	throw new AccessDeniedException("CA user can only revoke the certificates they issued");
	    cert.setRevoked(true);
	    cert.setRevocationReason(reason);
	    cert.setRevokedAt(LocalDateTime.now());

//	    if(user.getRole() == Role.USER)
//	        throw new AccessDeniedException("Users cannot revoke the certificates");
//
//	    if(checkIssuer(user, cert) && user.getRole() == Role.CA)
//	        throw new AccessDeniedException("CA user can only revoke the certificates they issued");

	    if(!getUsersCertificates(user).contains(cert))
	        throw new AccessDeniedException("Users can only revoke the certificates available to them");
	    
	    if(cert.isRevoked()) {
	        cert.setRevocationReason(reason);
	        cert.setRevokedAt(LocalDateTime.now());
	    } else {
	        cert.setRevoked(true);
	        cert.setRevocationReason(reason);
	        cert.setRevokedAt(LocalDateTime.now());
	    }

	    for (CertificateModel child : cert.getChildCertificates()) {
	        revokeCertificate(child, reason);
	    }
		
	    certRepo.save(cert);
		//TODO: Save crl to file in generate, and call generate from here - low priority who cares
	}
	
	public void rerevokeCertificate(CertificateModel cert) {
	    if (!cert.isRevoked())
	        throw new AccessDeniedException("This certificate is already unrevoked");
	    UserModel user = loggedUserUtils.getLoggedInUser();
//	    if(user.getRole() == Role.USER)
//	        throw new AccessDeniedException("Users cannot revoke the certificates");
//	    if(checkIssuer(user, cert) && user.getRole()==Role.CA)
//	    	throw new AccessDeniedException("CA user can only revoke the certificates they issued");

	    if(!getUsersCertificates(user).contains(cert))
	        throw new AccessDeniedException("Users can only unrevoke the certificates available to them");

	    cert.setRevoked(false);
//	    cert.setRevocationReason(reason);
	    cert.setRevokedAt(LocalDateTime.now());
	    for (CertificateModel child : cert.getChildCertificates()) {
	    	if(!child.isRevoked())
	    		continue;
	    	rerevokeCertificate(child);
	    }

	    certRepo.save(cert);
		//TODO: Save crl to file in generate, and call generate from here - low priority who cares
	}
	private boolean checkIssuer(UserModel user, CertificateModel cert) {
		Set<CertificateModel> certs = user.getCertificates();
		for(CertificateModel crt:certs) {
			if(crt.getChildCertificates().contains(cert))
				return true;
		}
		return false;
	
	}
}