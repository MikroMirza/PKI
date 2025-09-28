import { Component, Inject } from '@angular/core';
import { MatDialogRef, MAT_DIALOG_DATA } from '@angular/material/dialog';
import { CommonModule } from '@angular/common';
import { MatButtonModule } from '@angular/material/button';
import { CertificateService } from '../../Services/certificate.service';
import { RevokedCertificateDTO } from '../../DTO/Certificate/RevokedCertificateDTO';

@Component({
  selector: 'app-revoke-dialog',
  standalone: true,
  imports: [CommonModule, MatButtonModule],
  templateUrl: './revoke-reason-dialog.html',
  styleUrl: './revoke-reason-dialog.css'

})
export class RevokeDialogComponent {
  reasonOptions = [
    { code: 0, label: "Unspecified", description: "No specific reason provided." },
    { code: 1, label: "Key Compromise", description: "The certificate's private key has been compromised." },
    { code: 2, label: "CA Compromise", description: "The issuing CA’s key has been compromised." },
    { code: 3, label: "Affiliation Changed", description: "The subject’s details are no longer valid." },
    { code: 4, label: "Superseded", description: "The certificate has been replaced with a new one." },
    { code: 5, label: "Cessation of Operation", description: "The certificate is no longer required." },
    { code: 6, label: "Certificate Hold", description: "Temporary revocation requested by the certificate holder." },
    { code: 8, label: "Remove From CRL", description: "The certificate is removed from the CRL." },
    { code: 9, label: "Privilege Withdrawn", description: "The certificate holder’s privileges were revoked." },
    { code: 10, label: "AA Compromise", description: "The attribute authority’s private key was compromised." }
  ];

  selectedOptionIndex: number | null = 0;

  constructor(
    private certService: CertificateService,
    public dialogRef: MatDialogRef<RevokeDialogComponent>,
    @Inject(MAT_DIALOG_DATA) public data: { certId: number }
  ) {}

  selectOption(index: number) {
    this.selectedOptionIndex = index === this.selectedOptionIndex ? null : index;
  }

  onConfirm() {
    if (this.selectedOptionIndex === null) {
      alert("Please select a revocation reason.");
      return;
    }

    const dto: RevokedCertificateDTO = {
      certId: this.data.certId,
      reason: this.reasonOptions[this.selectedOptionIndex].code
    };

    this.certService.revokeCertificate(dto).subscribe({
      next: () => {
        alert("Certificate revoked successfully.");
        this.dialogRef.close(true);
      },
      error: () => alert("Failed to revoke certificate.")
    });
  }

  onCancel() {
    this.dialogRef.close(false);
  }
}
