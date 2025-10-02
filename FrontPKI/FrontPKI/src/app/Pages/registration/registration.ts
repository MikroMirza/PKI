import { ChangeDetectorRef, Component } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { UserService } from '../../Services/user.service';
import { Router } from '@angular/router';
import { RegisterUserDTO } from '../../DTO/User/RegisterUserDTO';
import { CommonModule } from '@angular/common';
import { MatHint } from '@angular/material/form-field';

@Component({
  selector: 'app-registration',
  standalone:true,
  imports: [FormsModule, CommonModule ],
  templateUrl: './registration.html',
  styleUrl: './registration.css'
})
export class RegistrationComponent {
  email:string='';
  password:string='';
  confirmPassword: string = '';
  name:string='';
  surname:string='';
  organization:string='';
  errorMessage:string='';

  emailTouched = false;
  passwordTouched = false;
  confirmPasswordTouched = false;
  nameTouched = false;
  surnameTouched = false;
  orgTouched = false;

  constructor(private userService: UserService, private cd: ChangeDetectorRef, private router: Router){}

  createClicked() {
  let data = new RegisterUserDTO();
  data.email = this.email;
  data.name = this.name;
  data.surname = this.surname;
  data.organization = this.organization;
  data.password = this.password;

  this.userService.creatRegularUser(data).subscribe({
    complete: () => {
      this.router.navigateByUrl("");
    },
    error: (err) => {
      this.errorMessage = err.error?.message || 'Unknown error';
      console.error("Validation error:", err.error); 
      this.cd.detectChanges();
    }
  });
}

  passStrength: String = "";
  checkPassStrength(){
    this.passwordTouched = true
    let strength = 0;

    if (this.password.length >= 6) strength++;
    if (/[A-Z]/.test(this.password)) strength++;
    if (/[0-9]/.test(this.password)) strength++;
    if (/[^A-Za-z0-9]/.test(this.password)) strength++;

    if (strength <= 1) {
      this.passStrength = 'Weak';
    } else if (strength === 2 || strength === 3) {
      this.passStrength = 'Medium';
    } else {
      this.passStrength = 'Strong';
    }
  }


  isValidEmail(val: string): boolean {
    return /^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+$/.test(val);
  }

  isValidPassword(val: string): boolean {
    return /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{6,}$/.test(val);
  }

  isValidName(val: string): boolean {
    return /^[A-Za-z]{2,}$/.test(val);
  }

  isValidSurname(val: string): boolean {
    return /^[A-Za-z]{2,}$/.test(val);
  }

  isValidOrg(val: string): boolean {
    return /^[A-Za-z0-9\s-]{3,}$/.test(val);
  }

  formValid(): boolean {
    return this.isValidEmail(this.email)
      && this.isValidPassword(this.password)
      && this.password === this.confirmPassword
      && this.isValidName(this.name)
      && this.isValidSurname(this.surname)
      && this.isValidOrg(this.organization);
  }
}
