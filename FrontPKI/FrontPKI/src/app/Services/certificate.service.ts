import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { SimpleCertificateDTO } from '../DTO/Certificate/SimpleCertificateDTO';
import { Observable } from 'rxjs';
import { environment } from '../env/environment';
import { CreateCertificateDTO } from '../DTO/Certificate/CreateIntermediateDTO';

@Injectable({
  providedIn: 'root'
})
export class CertificateService {

  constructor(private http: HttpClient) { }

  getCertificates(): Observable<SimpleCertificateDTO[]>{
    return this.http.get<SimpleCertificateDTO[]>(`${environment.apiHost}/api/certificates`);
  }

  createIntermediate(data: CreateCertificateDTO){
    return this.http.post(`${environment.apiHost}/api/certificates/intermediate`, data);
  }
}
