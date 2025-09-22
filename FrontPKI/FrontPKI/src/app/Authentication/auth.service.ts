import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { map, Observable, tap } from 'rxjs';
import { LoginDTO } from '../DTO/Auth/LoginDTO';
import { LoginResponseDTO } from '../DTO/Auth/LoginResponseDTO';
import { environment } from '../env/environment';
import { RefreshResponse } from '../DTO/Auth/RefreshResponse';
import { RefreshRequest } from '../DTO/Auth/RefreshRequest';
import { JwtHelperService } from '@auth0/angular-jwt';

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  public accessToken: string | null;
  public refreshTokenValue: string | null;

  constructor(private http: HttpClient){
    this.accessToken = localStorage.getItem('accessToken')
    this.refreshTokenValue = localStorage.getItem('refreshToken')
  }

  login(username: String, password: String): Observable<LoginResponseDTO> {
    let data = new LoginDTO();
    data.email = username;
    data.password = password;
    return this.http.post<LoginResponseDTO>(environment.apiHost + '/api/auth/login', data).pipe(
      tap((tokens: LoginResponseDTO) => {
        this.accessToken = tokens.jwt;
        this.refreshTokenValue = tokens.refresh;
        localStorage.setItem('accessToken', this.accessToken);
        localStorage.setItem('refreshToken', this.refreshTokenValue);
      })
    );
  }

  getAccessToken() {
    return this.accessToken || localStorage.getItem('accessToken');
  }

  getRefreshToken() {
    return this.refreshTokenValue || localStorage.getItem('refreshToken');
  }

  refreshToken(): Observable<RefreshResponse> {
    let data = new RefreshRequest();
    let token = this.getRefreshToken();
    if(token != null)
      data.token = token;
    return this.http.post<RefreshResponse>(environment.apiHost + '/api/auth/refresh', data).pipe(
      tap((response: RefreshResponse) => {
        this.accessToken = response.jwt;
        localStorage.setItem('accessToken', this.accessToken);
      })
    )
  }

  logout() {
    localStorage.clear();
    this.accessToken = null;
    this.refreshTokenValue = null;
  }

  isLoggedIn(): boolean {
    return typeof localStorage !== 'undefined' && localStorage.getItem('accessToken') != null;
  }

  getRole(): String | null{
    if (typeof localStorage !== 'undefined' && this.isLoggedIn()) {
      const accessToken: any = localStorage.getItem('accessToken');
      const helper = new JwtHelperService();
      return helper.decodeToken(accessToken).role;
    }
    return null;
  }
}
