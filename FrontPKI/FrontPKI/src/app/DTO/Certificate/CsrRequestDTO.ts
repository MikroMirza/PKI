export interface GenerateCertificateRequestDTO {
  commonName: string;
  organization: string;
  organizationalUnit: string;
  country: string;
  email: string;
  notBefore: string;
  notAfter: string; 
  issuerCertId: number;
}