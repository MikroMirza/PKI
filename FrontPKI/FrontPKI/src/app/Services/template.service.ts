import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { TemplateDTO } from '../DTO/Certificate/TemplateDTO';
import { HttpClient } from '@angular/common/http';
import { environment } from '../env/environment';

@Injectable({
  providedIn: 'root'
})
export class TemplateService {
  
  constructor(private http: HttpClient){}

  getTemplate(id: Number): Observable<TemplateDTO>{
    return this.http.get<TemplateDTO>(`${environment.apiHost}/api/certificates/templates/${id}`)
  }
  
  createTemplate(data: TemplateDTO){
    return this.http.post(`${environment.apiHost}/api/certificates/templates`, data)
  }

  deleteTemplate(id: Number){
    return this.http.delete(`${environment.apiHost}/api/certificates/templates/${id}`)
  }
}
