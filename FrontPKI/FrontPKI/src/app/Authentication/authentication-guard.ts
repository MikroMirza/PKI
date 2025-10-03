import { Injectable } from '@angular/core';
import { ActivatedRouteSnapshot, CanActivate, Router, UrlTree } from '@angular/router';
import { AuthService } from './auth.service';

@Injectable({
  providedIn: 'root'
})
export class AuthenticationGuard implements CanActivate{
  constructor(private router: Router, private authService: AuthService) {}
    
    canActivate(route: ActivatedRouteSnapshot): boolean | UrlTree{
      const userRole: String | null = this.authService.getRole()

      if (userRole == null || userRole == "") {
        return this.router.createUrlTree(["/"])
      }
      if (!route.data['role'].includes(userRole)) {
        return this.router.createUrlTree(["/"]);
      }

      return true;
    }
}
