import { Component, Inject, OnInit } from '@angular/core';
import { MAT_DIALOG_DATA, MatDialogRef } from '@angular/material/dialog';
import { CommonModule } from '@angular/common';
import { MatDialogModule } from '@angular/material/dialog';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatSelectModule } from '@angular/material/select';
import { MatDatepickerModule } from '@angular/material/datepicker';
import { MatNativeDateModule } from '@angular/material/core';
import { SimpleCertificateDTO } from '../../DTO/Certificate/SimpleCertificateDTO';
import { CertificateService } from '../../Services/certificate.service';
import { FormsModule } from '@angular/forms';

@Component({
  selector: 'app-csr-dialog-component',
  standalone: true,
  imports: [
    CommonModule,
    FormsModule,
    MatDialogModule,
    MatFormFieldModule,
    MatInputModule,
    MatButtonModule,
    MatIconModule,
    MatSelectModule,
    MatDatepickerModule,
    MatNativeDateModule,
  ],
  templateUrl: './csr-dialog-component.html',
  styleUrls: ['./csr-dialog-component.css']
})
export class CsrDialogComponent implements OnInit {
  notBefore!: Date;
  notAfter!: Date;
  csrFile?: File;
  errorMessage: string | null = null;

  issuers: SimpleCertificateDTO[] = [];
  selectedIssuerId?: number;

  constructor(
    public dialogRef: MatDialogRef<CsrDialogComponent>,
    @Inject(MAT_DIALOG_DATA) public data: { cert?: SimpleCertificateDTO },
    private certService: CertificateService
  ) {}

  ngOnInit(): void {
    this.certService.getAvailableCACertificates().subscribe({
      next: (certs) => {
        this.issuers = certs;
        if (!this.selectedIssuerId && certs.length) {
          this.selectedIssuerId = certs[0].id;
        }
      },
      error: (err) => console.error('Error loading issuers', err)
    });
  }

  onFileSelected(event: any) {
    this.csrFile = event.target.files[0];
  }


onGenerate() {
  if (!this.csrFile || !this.notBefore || !this.notAfter || !this.selectedIssuerId) {
    this.errorMessage = "Please fill in all required fields.";
    return;
  }

  this.certService.createCertificateFromCsr(
    this.csrFile,
    this.selectedIssuerId,
    this.notBefore,
    this.notAfter
  ).subscribe({
    next: (res) => {
      console.log('Certificate generated from CSR', res);
      this.dialogRef.close(res);
    },
    error: (err) => {
      this.errorMessage = err.error?.message || 'Error generating certificate';
      console.error('Error generating certificate', err);
    }
  });
}


  onCancel() {
    this.dialogRef.close();
  }
}
