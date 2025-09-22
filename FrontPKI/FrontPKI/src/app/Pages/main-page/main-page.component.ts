import { Component } from '@angular/core';
import { AuthService } from '../../Authentication/auth.service';
import { NavigationEnd, Router } from '@angular/router';
import { filter } from 'rxjs';
import { CommonModule } from '@angular/common';
import { RouterLink } from '@angular/router';

@Component({
  selector: 'app-main-page',
  standalone: true,
  imports: [CommonModule, RouterLink],
  templateUrl: './main-page.component.html',
  styleUrl: './main-page.component.css'
})
export class MainPageComponent {
  constructor(private authService: AuthService, private router: Router){}
  
  role: String = "";

  ngOnInit(){
    this.router.events.subscribe(event => {
      if (event instanceof NavigationEnd)
        this.role = this.authService?.getRole() ?? ""
    })
    this.role = this.authService?.getRole() ?? ""
  }
  logout(){
    this.authService.logout;
  }
}
