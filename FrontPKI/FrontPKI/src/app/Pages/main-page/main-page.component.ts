import { Component } from '@angular/core';
import { AuthService } from '../../Authentication/auth.service';
import { ActivatedRoute, NavigationEnd, Router, RouterModule } from '@angular/router';
import { filter, Observable } from 'rxjs';
import { CommonModule } from '@angular/common';
import { RouterLink } from '@angular/router';
import { SimpleCertificateDTO } from '../../DTO/Certificate/SimpleCertificateDTO';
import { CertificateService } from '../../Services/certificate.service';
import { CertificateTableComponent } from "../../Components/Data/certificate-table/certificate-table.component";

@Component({
  selector: 'app-main-page',
  standalone: true,
  imports: [CommonModule, RouterModule, RouterLink, CertificateTableComponent],
  templateUrl: './main-page.component.html',
  styleUrl: './main-page.component.css'
})
export class MainPageComponent {
  constructor(
    private authService: AuthService,
    private router: Router,
    private route: ActivatedRoute,
    private certService: CertificateService){}
  
  role: String = "";
  certData$!: Observable<SimpleCertificateDTO[]>;

  ngOnInit(){
    this.route.url.subscribe(() => {
        this.role = this.authService?.getRole() ?? ""
        this.certData$ = this.certService.getCertificates()
      })
  }
  logout(){
    this.authService.logout();
  }
}
