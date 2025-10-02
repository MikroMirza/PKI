import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { SimpleCertificateDTO } from '../DTO/Certificate/SimpleCertificateDTO';
import { Observable } from 'rxjs';
import { environment } from '../env/environment';
import { CreateCertificateDTO } from '../DTO/Certificate/CreateCertificateDTO';
import { RevokedCertificateDTO } from '../DTO/Certificate/RevokedCertificateDTO';
import { GenerateCertificateRequestDTO } from '../DTO/Certificate/CsrRequestDTO';
import { TemplateDTO } from '../DTO/Certificate/TemplateDTO';
import { CsrRequestDTO } from '../DTO/Certificate/CsrRequestState';
import { CertificateDetailsDTO } from '../DTO/Certificate/CertificateDetailsDTO';

@Injectable({
  providedIn: 'root'
})
export class CertificateService {

  constructor(private http: HttpClient) { }

  getCertificateTemplates(id: number){
    return this.http.get<TemplateDTO[]>(`${environment.apiHost}/api/certificates/${id}/templates`);
  }

  
  getCertificateDetails(id: number){
    return this.http.get<CertificateDetailsDTO>(`${environment.apiHost}/api/certificates/${id}`);
  }

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
  
  rerevokeCertificate(data:RevokedCertificateDTO){
    return this.http.post(`${environment.apiHost}/api/certificates/rerevoked`,data)
  }

  createCsrRequest(dto: GenerateCertificateRequestDTO): Observable<any> {
    return this.http.post(`${environment.apiHost}/api/certificates/generate`, dto);
  }

  issueFromRequest(requestId: number): Observable<any> {
    return this.http.post(`${environment.apiHost}/api/certificates/issue/${requestId}`, {});
  }

  createCertificateFromCsr(
    csrFile: File,
    issuerId: number,
    notBefore: Date,
    notAfter: Date
  ): Observable<any> {
    return new Observable(observer => {
      const reader = new FileReader();
      reader.onload = () => {
        const csrPem = reader.result as string;

        const dto: CsrRequestDTO = {
          csrPem,
          issuerId,
          notBefore: notBefore.toISOString().split('T')[0],
          notAfter: notAfter.toISOString().split('T')[0]
        };

        this.http.post(`${environment.apiHost}/api/certificates/from-csr`, dto)
          .subscribe({
            next: res => observer.next(res),
            error: err => observer.error(err),
            complete: () => observer.complete()
          });
      };
      reader.readAsText(csrFile);
    });
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
