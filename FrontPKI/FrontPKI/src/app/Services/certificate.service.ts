import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { SimpleCertificateDTO } from '../DTO/Certificate/SimpleCertificateDTO';
import { Observable } from 'rxjs';
import { environment } from '../env/environment';
import { CreateCertificateDTO } from '../DTO/Certificate/CreateCertificateDTO';
import { RevokedCertificateDTO } from '../DTO/Certificate/RevokedCertificateDTO';
import { CsrRequest } from '../DTO/Certificate/CsrRequestDTO';

@Injectable({
  providedIn: 'root'
})
export class CertificateService {

  constructor(private http: HttpClient) { }

  getAllCertificates(): Observable<SimpleCertificateDTO[]>{
    return this.http.get<SimpleCertificateDTO[]>(`${environment.apiHost}/api/certificates`);
  }

  getAvailableCertificates(): Observable<SimpleCertificateDTO[]>{
    return this.http.get<SimpleCertificateDTO[]>(`${environment.apiHost}/api/certificates/available`);
  }

  getAvailableCACertificates(): Observable<SimpleCertificateDTO[]>{
    return this.http.get<SimpleCertificateDTO[]>(`${environment.apiHost}/api/certificates/availableCA`);
  }

  createCertificate(data: CreateCertificateDTO){
    return this.http.post(`${environment.apiHost}/api/certificates`, data);
  }

  revokeCertificate(data:RevokedCertificateDTO){
    return this.http.post(`${environment.apiHost}/api/certificates/revoked`,data)
  }

  createCsrRequest(dto: CsrRequest): Observable<any> {
    return this.http.post(`${environment.apiHost}/api/certificates/request`, dto);
  }

  issueFromRequest(requestId: number): Observable<any> {
    return this.http.post(`${environment.apiHost}/api/certificates/issue/${requestId}`, {});
  }

  downloadCertificate(certId: number, password: string) {
    this.http.post(`${environment.apiHost}/api/certificates/${certId}/download`, password, {
    responseType: 'blob'
  }).subscribe(blob => {
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = "certificate.p12";
    a.click();
    window.URL.revokeObjectURL(url);
  });
}

}
