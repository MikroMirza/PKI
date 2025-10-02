import { ChangeDetectorRef, Component } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatError } from '@angular/material/form-field';

import { RegisterUserDTO } from '../../DTO/User/RegisterUserDTO';
import { UserService } from '../../Services/user.service';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-create-ca-user',
  standalone: true,
  imports: [
    CommonModule,
    FormsModule,
    MatFormFieldModule,
    MatInputModule,
    MatButtonModule,
    MatIconModule
  ],
  templateUrl: './create-ca-user.component.html',
  styleUrls: ['./create-ca-user.component.css']
})
export class CreateCaUserComponent {
  email: string = "";
  name: string = "";
  surname: string = "";
  organization: string = "";
  password: string = "";
  hidePassword = true;

  errorMessage: string = "";

  constructor(private userService: UserService, private cd: ChangeDetectorRef, private router: Router) {}

  createClicked() {
    let data = new RegisterUserDTO();
    data.email = this.email;
    data.name = this.name;
    data.surname = this.surname;
    data.organization = this.organization;
    data.password = this.password;

    this.userService.createCaUser(data).subscribe({
      complete: () => {
        this.router.navigateByUrl("/mainpage");
      },
      error: (err) => {
        this.errorMessage = err.error?.message || 'Unknown error';
        console.error("Validation error:", err.error);
        this.cd.detectChanges();
      }
    });
  }
}
