import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable } from 'rxjs';
import { environment } from '../env/environment';

@Injectable({
  providedIn: 'root'
})
export class CRLService {


  constructor(private http: HttpClient) { }
  getCRL(issuerCertId: number): Observable<ArrayBuffer> {
    const headers = new HttpHeaders({
      'Accept': 'application/pkix-crl'
    });
    return this.http.get(`${environment.apiHost}/crl/${issuerCertId}`, { headers, responseType: 'arraybuffer' });
  }

  
}
