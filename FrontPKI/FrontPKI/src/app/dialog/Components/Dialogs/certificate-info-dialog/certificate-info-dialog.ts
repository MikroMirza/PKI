import { Component, Inject } from '@angular/core';
import { MAT_DIALOG_DATA, MatDialogRef } from '@angular/material/dialog';
import { SimpleCertificateDTO } from '../../../../DTO/Certificate/SimpleCertificateDTO';
import { MatTabsModule } from '@angular/material/tabs';
import { CommonModule } from '@angular/common';
import { MatButtonModule } from '@angular/material/button';
import { CertificateDetailsDTO } from '../../../../DTO/Certificate/CertificateDetailsDTO';

@Component({
  selector: 'app-certificate-info-dialog',
  standalone: true,
  imports: [CommonModule, MatTabsModule, MatButtonModule],
  templateUrl: './certificate-info-dialog.html',
  styleUrls: ['./certificate-info-dialog.css']
})
export class CertificateInfoDialogComponent {
  constructor(
    public dialogRef: MatDialogRef<CertificateInfoDialogComponent>,
    @Inject(MAT_DIALOG_DATA) public certDetails: CertificateDetailsDTO
  ) {}

  message: String = "";

  close() {
    this.dialogRef.close();
  }
}
