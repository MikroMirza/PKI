import { HttpClient, HttpHeaders } from "@angular/common/http";
import { Injectable } from "@angular/core";
import { environment } from "../env/environment";
import { Observable } from "rxjs";
import { VerificationResponse } from "../common/VerificationResponse";



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

}
