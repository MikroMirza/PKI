import { HttpClient, HttpHeaders } from "@angular/common/http";
import { Injectable } from "@angular/core";
import { environment } from "../env/environment";
import { Observable } from "rxjs";
import { VerificationResponse } from "../common/VerificationResponse";
import { RegisterUserDTO } from "../DTO/User/RegisterUserDTO";
import { SimpleUserDTO } from "../DTO/User/SimpleUserDTO";



@Injectable({
    providedIn: 'root',
})
export class UserService {
  private headers = new HttpHeaders({
      'Content-Type': 'application/json'
  });
  constructor(private http: HttpClient) {}


    verifyUser(token: string): Observable<VerificationResponse> {
    return this.http.get<VerificationResponse>(`${environment.apiHost}/api/users/verification`, {
      headers: this.headers,
      params: { token }
    });
  }

  creatRegularUser(data: RegisterUserDTO){
    return this.http.post(`${environment.apiHost}/api/users/regular`, data)
  }

  createCaUser(data: RegisterUserDTO){
    return this.http.post(`${environment.apiHost}/api/users/ca`, data)
  }

  getUsers(): Observable<SimpleUserDTO[]>{
    return this.http.get<SimpleUserDTO[]>(`${environment.apiHost}/api/users`)
  }

  getUser(id: number): Observable<SimpleUserDTO>{
    return this.http.get<SimpleUserDTO>(`${environment.apiHost}/api/users/${id}`)
  }

  giveUserCertificate(userId: number, certId: number){
    return this.http.post(`${environment.apiHost}/api/users/${userId}/certificates`, certId, {
      observe: 'response'
    })
  }

  removeUsersCertificate(userId: number, certId: number){
    return this.http.delete(`${environment.apiHost}/api/users/${userId}/certificates/${certId}`, {
      observe: 'response'
    })
  }
}
