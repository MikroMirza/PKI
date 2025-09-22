import { Routes } from '@angular/router';
import { Verification } from './Authentication/verification/verification/verification';
import { LoginpageComponent } from './Pages/loginpage/loginpage.component';
import { MainPageComponent } from './Pages/main-page/main-page.component';
import { CreateCaUserComponent } from './Pages/create-ca-user/create-ca-user.component';
import { RegistrationComponent  } from './Pages/registration/registration';

export const routes: Routes = [
  {path: 'authentication/verification', component: Verification},
  {path: 'mainpage', component: MainPageComponent},
  {path: 'users/ca/new', component: CreateCaUserComponent},
  {path: 'users/new', component: RegistrationComponent},
  // {path: 'certificates/ca/new', component: Verification},
  {path: '', component: LoginpageComponent}
];
