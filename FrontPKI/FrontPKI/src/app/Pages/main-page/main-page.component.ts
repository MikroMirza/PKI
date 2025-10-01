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
import { ExportPasswordDialogComponent } from '../../dialog/export-password-dialog-component/export-password-dialog-component';
import { SelectCertificate } from "../../Components/Data/select-certificate/select-certificate";
import { CRLService } from '../../Services/crl.service';
import { GenerateCertificateComponent } from '../generate-certificate/generate-certificate.component';
import { GenerateCsrComponent } from '../generate-csr/generate-csr';

@Component({
  selector: 'app-main-page',
  standalone: true,
  imports: [CommonModule, RouterModule, RouterLink, SelectCertificate],
  templateUrl: './main-page.component.html',
  styleUrl: './main-page.component.css'
})
export class MainPageComponent {
  constructor(
    private authService: AuthService,
    private router: Router,
    private route: ActivatedRoute,
    private certService: CertificateService,
    private crlService: CRLService,
    private dialog:MatDialog){}
  selectedCert: SimpleCertificateDTO | null = null;

  role: String = "";
  certData$!: Observable<SimpleCertificateDTO[]>;

  ngOnInit(){
    this.route.url.subscribe(() => {
        this.role = this.authService?.getRole() ?? ""
        this.certData$ = this.certService.getAllCertificates()
      })
  }
  logout(){
    this.authService.logout();
  }

  onSelectCert(cert: SimpleCertificateDTO) {
    this.selectedCert = cert;
    console.log(this.selectedCert)
  }

  openRevokeDialog() {
  console.log("GAs1")
  if (this.selectedCert == null) return;

  console.log("GAs2")

  const dialogRef = this.dialog.open(RevokeDialogComponent, {
    data: { certId: this.selectedCert.id }
  });
  console.log("GAs3")

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
exportCertificate() {
  if (!this.selectedCert) return;

  const cert = this.selectedCert;
  const dialogRef = this.dialog.open(ExportPasswordDialogComponent, {
    width: '300px'
  });

  dialogRef.afterClosed().subscribe(password => {
    if (!password) return;

    this.certService.downloadCertificate(cert.id, password);
  });
}
// openCSR() {
//   this.dialog.open(GenerateCsrComponent);
// }

  

showCrl(){
  const decoder = new TextDecoder("UTF-8");
  this.crlService.getCRL(3).subscribe({
    next: (data) => console.log(Array.from(new Uint8Array(data)).map((b) => b.toString(16).padStart(2, "0")).join(""))
  })
}
}

