import { Component } from '@angular/core';
import { AuthService } from '../../Authentication/auth.service';
import { ActivatedRoute, NavigationEnd, Router, RouterModule } from '@angular/router';
import { filter, Observable } from 'rxjs';
import { CommonModule } from '@angular/common';
import { RouterLink } from '@angular/router';
import { SimpleCertificateDTO } from '../../DTO/Certificate/SimpleCertificateDTO';
import { CertificateService } from '../../Services/certificate.service';
import { CertificateTableComponent } from "../../Components/Data/certificate-table/certificate-table.component";
import { MatDialog } from '@angular/material/dialog';
import { RevokeDialogComponent } from '../../dialog/revoke-reason-dialog/revoke-reason-dialog';

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
    private certService: CertificateService,
    private dialog:MatDialog){}
  selectedCert: SimpleCertificateDTO | null = null;

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

  onSelectCert(cert: SimpleCertificateDTO) {
    this.selectedCert = cert;
  }
  openRevokeDialog() {
  if (!this.selectedCert) return;

  const dialogRef = this.dialog.open(RevokeDialogComponent, {
    data: { certId: this.selectedCert.id }
  });

  dialogRef.afterClosed().subscribe((revoked: boolean) => {
    if (revoked && this.selectedCert) {
      this.markRevoked(this.selectedCert);
    }
  });
}

markRevoked(cert: SimpleCertificateDTO) {
  cert.isRevoked = true;
  if (cert.children) {
    cert.children.forEach(child => this.markRevoked(child));
  }
}

}

