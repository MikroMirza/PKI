import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { TemplateDTO } from '../DTO/Certificate/TemplateDTO';
import { HttpClient } from '@angular/common/http';

@Injectable({
  providedIn: 'root'
})
export class TemplateService {
  
  constructor(private http: HttpClient){}

  getTemplate(id: Number){
    
  }
  
  createTemplate(data: TemplateDTO){

  }

  
}
