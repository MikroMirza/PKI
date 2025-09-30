export interface CsrRequest {
  commonName: string;
  organization: string;
  organizationalUnit: string;
  country: string;
  email: string;
  notBefore: string;
  notAfter: string; 
}