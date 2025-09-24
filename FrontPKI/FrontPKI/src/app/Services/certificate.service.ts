import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { SimpleCertificateDTO } from '../DTO/Certificate/SimpleCertificateDTO';
import { Observable } from 'rxjs';
import { environment } from '../env/environment';
import { CreateCertificateDTO } from '../DTO/Certificate/CreateCertificateDTO';

@Injectable({
  providedIn: 'root'
})
export class CertificateService {

  constructor(private http: HttpClient) { }

  getCertificates(): Observable<SimpleCertificateDTO[]>{
    return this.http.get<SimpleCertificateDTO[]>(`${environment.apiHost}/api/certificates`);
  }

  createCA(data: CreateCertificateDTO){
    return this.http.post(`${environment.apiHost}/api/certificates/ca`, data);
  }

  createNonCA(data: CreateCertificateDTO){
    return this.http.post(`${environment.apiHost}/api/certificates/non-ca`, data);
  }
}
