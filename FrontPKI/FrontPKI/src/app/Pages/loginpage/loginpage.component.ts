import { HttpClient } from '@angular/common/http';
import { ChangeDetectorRef, Component } from '@angular/core';
import { AuthService } from '../../Authentication/auth.service';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { NavigationEnd, Router } from '@angular/router';
import { RouterLink } from '@angular/router';

@Component({
  selector: 'app-loginpage',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './loginpage.component.html',
  styleUrls: ['./loginpage.component.css']
})
export class LoginpageComponent {
  errorMessage: string = "";
  email: string = "";
  password: string = "";

  constructor(private authService: AuthService, private cd: ChangeDetectorRef, private router: Router){}

  ngOnInit(){
    console.log(this.authService.getAccessToken())
    console.log(this.authService.refreshTokenValue)
    console.log(this.authService.getRole())
    this.router.events.subscribe(event => {
      if (event instanceof NavigationEnd)
        if(this.authService.isLoggedIn())
          this.router.navigateByUrl("/mainpage");
    })
  }

  login() {
      this.authService.login(this.email, this.password).subscribe({
        complete: () => {
          console.log(this.authService.getRole());
          this.router.navigateByUrl("/mainpage");
        },
        error: (err) => {
          this.errorMessage = err.error?.message || 'Unknown error';
          this.cd.detectChanges()
        }
      });
  }
  register() {
    this.router.navigateByUrl("/users/new");
  }
}
