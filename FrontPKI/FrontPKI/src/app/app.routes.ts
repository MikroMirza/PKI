import { Routes } from '@angular/router';
import { Verification } from './Authentication/verification/verification/verification';
import { LoginpageComponent } from './Pages/loginpage/loginpage.component';
import { MainPageComponent } from './Pages/main-page/main-page.component';
import { CreateCaUserComponent } from './Pages/create-ca-user/create-ca-user.component';
import { RegistrationComponent  } from './Pages/registration/registration';
import { GenerateCertificateComponent } from './Pages/generate-certificate/generate-certificate.component';
import { GiveUserCertPage } from './Pages/give-user-cert-page/give-user-cert-page';
import { CreateTemplatePage } from './Pages/create-template-page/create-template-page';
import { GenerateCsrComponent } from './Pages/generate-csr/generate-csr';

export const routes: Routes = [
  {path: 'authentication/verification', component: Verification},
  {path: 'mainpage', component: MainPageComponent},
  {path: 'create-certificate', component: GenerateCertificateComponent},
  {path: 'create-template', component: CreateTemplatePage},
  {path:'CSR',component:GenerateCsrComponent},
  {path: 'assign-ca', component: GiveUserCertPage},
  {path: 'users/ca/new', component: CreateCaUserComponent},
  {path: 'users/new', component: RegistrationComponent},
  {path: '', component: LoginpageComponent}
];
