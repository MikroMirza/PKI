package rs.tim33.PKI.DTO.Certificate;

import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.List;

import rs.tim33.PKI.Models.CertificateModel;

public class CertificateDetailsDTO {
	public List<StringPair> details = new ArrayList<StringPair>();
	public List<StringPair> subjectPublicKeyInfo = new ArrayList<StringPair>();
	public List<StringPair> validity = new ArrayList<StringPair>();
	public List<StringPair> extensions = new ArrayList<StringPair>();
	
	public CertificateDetailsDTO(CertificateModel certModel) {
		try {
			X509Certificate cert = certModel.getCertificate();
			details.add(new StringPair("Serial Number", cert.getSerialNumber().toString(16)));
			details.add(new StringPair("Subject", cert.getSubjectX500Principal().getName()));
			details.add(new StringPair("Issuer", cert.getIssuerX500Principal().getName()));

			details.add(new StringPair("Certificate Signature Algorithm", cert.getSigAlgName()));
			details.add(new StringPair("Certificate Signature Algorithm", Base64.getEncoder().encodeToString(cert.getSignature())));
			
			subjectPublicKeyInfo.add(new StringPair("Public Key Algorithm", cert.getPublicKey().getAlgorithm()));
			subjectPublicKeyInfo.add(new StringPair("Public Key", Base64.getEncoder().encodeToString(cert.getPublicKey().getEncoded())));

			validity.add(new StringPair("Not Before", cert.getNotBefore().toGMTString()));
			validity.add(new StringPair("Not After", cert.getNotAfter().toGMTString()));
			
			if(cert.getBasicConstraints() == -1)
				extensions.add(new StringPair("Basic Constraints", "Not a Certificate Authority"));
			else
				extensions.add(new StringPair("Basic Constraints", "Is a Certificate Authority\nMaximum number of intermediate authorities: " + Integer.toString(cert.getBasicConstraints())));
			
			boolean[] keyUsage = cert.getKeyUsage();
			String keyUsageStr = "";
			if (keyUsage != null) {
			    String[] usages = {
			        "digitalSignature", "nonRepudiation", "keyEncipherment",
			        "dataEncipherment", "keyAgreement", "keyCertSign",
			        "cRLSign", "encipherOnly", "decipherOnly"
			    };

			    for (int i = 0; i < keyUsage.length; i++) {
			        if (keyUsage[i]) {
			        	keyUsageStr += usages[i] + "\n";
			        }
			    }
			}
			if(keyUsageStr.equals(""))
				extensions.add(new StringPair("Certificate Key Usage", keyUsageStr));
			
			List<String> eku = cert.getExtendedKeyUsage();
			String ekuStr = "";
			if (eku != null) {
			    for (String oid : eku) {
			        ekuStr += "Extended Key Usage OID: " + oid + "\n";
			    }
			}
			if(ekuStr.equals(""))
				extensions.add(new StringPair("Certificate Extended Key Usage", ekuStr));
			
			Collection<List<?>> sans = null;
			try {
			    sans = cert.getSubjectAlternativeNames();
			} catch (CertificateParsingException e) {
			    System.out.println("Failed to parse SAN extension: " + e.getMessage());
			}

			if (sans != null) {
			    for (List<?> san : sans) {
			        Integer type = (Integer) san.get(0);
			        Object value = san.get(1);
			        System.out.println("SAN (type " + type + "): " + value);
			    }
			} else {
			    System.out.println("No SANs present in certificate");
			}
			
				
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
