import { ChangeDetectorRef, Component } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { UserService } from '../../Services/user.service';
import { Router } from '@angular/router';
import { RegisterUserDTO } from '../../DTO/User/RegisterUserDTO';

@Component({
  selector: 'app-registration',
  standalone:true,
  imports: [FormsModule],
  templateUrl: './registration.html',
  styleUrl: './registration.css'
})
export class RegistrationComponent {
  email:string='';
  password:string='';
  name:string='';
  surname:string='';
  organization:string='';
  errorMessage:string='';

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
}
