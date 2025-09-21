import { HttpClient, HttpHeaders } from "@angular/common/http";
import { Injectable } from "@angular/core";
import { environment } from "../env/environment";
import { Observable } from "rxjs";
import { VerificationResponse } from "../common/VerificationResponse";
import { RegisterUserDTO } from "../DTO/User/RegisterUserDTO";



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

  createCaUser(data: RegisterUserDTO){
    return this.http.post(`${environment.apiHost}/api/users/ca`, data)
  }

}
