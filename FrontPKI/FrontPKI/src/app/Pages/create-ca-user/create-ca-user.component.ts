import { ChangeDetectorRef, Component } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RegisterUserDTO } from '../../DTO/User/RegisterUserDTO';
import { UserService } from '../../Services/user.service';
import { Router } from '@angular/router';

@Component({
  selector: 'app-create-ca-user',
  standalone: true,
  imports: [FormsModule],
  templateUrl: './create-ca-user.component.html',
  styleUrl: './create-ca-user.component.css'
})
export class CreateCaUserComponent {
  email: string = "";
  name: string = "";
  surname: string = "";
  organization: string = "";
  password: string = "";

  errorMessage: string = "";

  constructor(private userService: UserService, private cd: ChangeDetectorRef, private router: Router){}

  createClicked(){
    let data = new RegisterUserDTO();
    data.email = this.email;
    data.name = this.name;
    data.surname = this.surname;
    data.organization = this.organization;
    data.password = this.password;

    this.userService.createCaUser(data).subscribe({
      complete: () => {
        this.router.navigateByUrl("/mainpage")
      },
      error: (err) => {
        this.errorMessage = err.error?.message || 'Unknown error';
        this.cd.detectChanges();
      }
    })
  }
}
