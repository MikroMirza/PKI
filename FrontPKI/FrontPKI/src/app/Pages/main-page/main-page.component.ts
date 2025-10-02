import { Component } from '@angular/core';
import { AuthService } from '../../Authentication/auth.service';
import { ActivatedRoute, Router } from '@angular/router';
import { Observable } from 'rxjs';
import { CommonModule } from '@angular/common';
import { RouterLink } from '@angular/router';
import { SimpleCertificateDTO } from '../../DTO/Certificate/SimpleCertificateDTO';
import { CertificateService } from '../../Services/certificate.service';
import { MatDialog } from '@angular/material/dialog';
import { RevokeDialogComponent } from '../../dialog/revoke-reason-dialog/revoke-reason-dialog';
import { ExportPasswordDialogComponent } from '../../dialog/export-password-dialog-component/export-password-dialog-component';
import { CRLService } from '../../Services/crl.service';
import { CsrDialogComponent } from '../../dialog/csr-dialog-component/csr-dialog-component';
import { RevokedCertificateDTO } from '../../DTO/Certificate/RevokedCertificateDTO';
import { BasicCertificateDataComponent } from "../../Components/Data/basic-certificate-data/basic-certificate-data.component";
import { CardComponent } from "../../Components/Containers/card/card.component";
import { CertificateInfoDialogComponent } from '../../dialog/Components/Dialogs/certificate-info-dialog/certificate-info-dialog';

@Component({
  selector: 'app-main-page',
  standalone: true,
  imports: [CommonModule, RouterLink, BasicCertificateDataComponent, CardComponent],
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
    private dialog: MatDialog
  ) {}

  role: String = "";
  certData$!: Observable<SimpleCertificateDTO[]>;
  selectedCert: SimpleCertificateDTO | null = null;

  ngOnInit() {
    this.route.url.subscribe(() => {
      this.role = this.authService?.getRole() ?? "";
      this.certData$ = this.certService.getAllCertificates();
    });
  }

  logout() {
    this.authService.logout();
    this.router.navigate(['/']);
  }

  onSelectCert(cert: SimpleCertificateDTO) {
    this.selectedCert = cert;
  }

  onUnselectCert(cert: SimpleCertificateDTO) {
    if (this.selectedCert === cert) {
      this.selectedCert = null;
    }
  }
  openRevokeDialog(cert: SimpleCertificateDTO) {
    const dialogRef = this.dialog.open(RevokeDialogComponent, {
      data: { certId: cert.id }
    });

    dialogRef.afterClosed().subscribe((revoked: boolean) => {
      if (revoked) {
        cert.isRevoked = true;
      }
    });
  }

  unrevokeSelectedCert(cert: SimpleCertificateDTO) {
    const dto: RevokedCertificateDTO = {
      certId: cert.id,
      reason: 6
    };

    this.certService.rerevokeCertificate(dto).subscribe({
      next: () => {
        cert.isRevoked = false;
      },
      error: (err) => {
        if (err.error && err.error.message) {
          alert(err.error.message);
        } else {
          alert("Failed to unrevoke certificate.");
        }
      }
    });
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

  openCsrDialog() {
    this.dialog.open(CsrDialogComponent, { width: '500px' });
  }

showCrl() {
  if (!this.selectedCert) {
    alert("Please select a certificate first.");
    return;
  }
  const cert = this.selectedCert;
  this.crlService.getCRL(cert.id).subscribe({
    next: (data: ArrayBuffer) => {
      const bytes = new Uint8Array(data);

      const hexString = Array.from(bytes)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
      console.log(hexString);

      const blob = new Blob([data], { type: 'application/pkix-crl' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `crl-${cert.id}.crl`;
      a.click();
      window.URL.revokeObjectURL(url);
    },
    error: (err) => {
      alert(err.error?.message || "Cannot show CRL for this certificate");
    }
  });
}


  openCertDetails(cert: SimpleCertificateDTO) {

    this.certService.getCertificateDetails(cert.id).subscribe({
      next: (data) => {
        this.dialog.open(CertificateInfoDialogComponent, {
          width: '500px',
          height: '700px',
          data: data
        });
      }
    })
  }

}
