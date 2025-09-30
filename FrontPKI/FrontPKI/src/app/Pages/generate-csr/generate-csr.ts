import { CommonModule } from '@angular/common';
import { ChangeDetectorRef, Component } from '@angular/core';
import { FormBuilder, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { CertificateService } from '../../Services/certificate.service';
import { CsrRequest } from '../../DTO/Certificate/CsrRequestDTO';

@Component({
  selector: 'app-generate-csr',
  imports: [
  CommonModule,
  ReactiveFormsModule,
  MatButtonModule,
  MatInputModule,
  MatFormFieldModule],
  templateUrl: './generate-csr.html',
  styleUrl: './generate-csr.css'
})
export class GenerateCsrComponent {
  csrForm!: FormGroup;
  errorMessage: string = '';
  successMessage: string = '';

  constructor(
    private fb: FormBuilder,
    private certService: CertificateService,
    private cd: ChangeDetectorRef
  ) {}

  ngOnInit(): void {
    this.csrForm = this.fb.group({
      commonName: ['', Validators.required],
      organization: [''],
      organizationalUnit: [''],
      country: ['', [Validators.required, Validators.minLength(2), Validators.maxLength(2)]],
      email: ['', [Validators.required, Validators.email]],
      notBefore: ['', Validators.required],
      notAfter: ['', Validators.required],
      password: ['', Validators.required],
    });
  }

  submit() {
    if (this.csrForm.valid) {
      const dto: CsrRequest = {
        commonName: this.csrForm.value.commonName,
        organization: this.csrForm.value.organization,
        organizationalUnit: this.csrForm.value.organizationalUnit,
        country: this.csrForm.value.country,
        email: this.csrForm.value.email,
        notBefore: this.csrForm.value.notBefore,
        notAfter: this.csrForm.value.notAfter,
      };

      this.certService.createCsrRequest(dto).subscribe({
        next: (resp: any) => {
          this.successMessage = 'CSR successfully created!';
          this.errorMessage = '';
          this.cd.detectChanges();
          const certId = resp.certId || resp.id; 
          this.certService.downloadCertificate(certId, this.csrForm.value.password);
        },
        error: (err) => {
          this.errorMessage = err.error?.message || 'Error creating CSR';
          this.successMessage = '';
          this.cd.detectChanges();
        }
      });
    }
  }
}