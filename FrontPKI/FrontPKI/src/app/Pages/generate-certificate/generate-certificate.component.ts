import { CommonModule } from '@angular/common';
import { ChangeDetectorRef, Component } from '@angular/core';
import { FormArray, FormBuilder, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { MatCheckboxModule } from '@angular/material/checkbox';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { CertType } from '../../common/CertType';
import { SelectCertificate } from "../../Components/Data/select-certificate/select-certificate";
import { ActivatedRoute } from '@angular/router';
import { CertificateService } from '../../Services/certificate.service';
import { Observable } from 'rxjs';
import { SimpleCertificateDTO } from '../../DTO/Certificate/SimpleCertificateDTO';

@Component({
  selector: 'app-generate-certificate',
  standalone: true,
  imports: [ReactiveFormsModule, CommonModule, MatIconModule, MatSelectModule, MatButtonModule, MatCheckboxModule, MatInputModule, MatFormFieldModule, SelectCertificate],
  templateUrl: './generate-certificate.component.html',
  styleUrl: './generate-certificate.component.css'
})
export class GenerateCertificateComponent {
  certificateForm!: FormGroup;
  certTypes = ['ROOT', 'INTERMEDIATE', 'END_ENTITY']
  certData: Observable<SimpleCertificateDTO[]> = new Observable<SimpleCertificateDTO[]>();

  constructor(
    private fb: FormBuilder,
    private activatedRoute: ActivatedRoute,
    private certService: CertificateService,
    private cd: ChangeDetectorRef) {}

  reloadCerts(){
    this.certData = this.certService.getAvailableCACertificates();
    this.cd.detectChanges();
  }

  ngOnInit(): void {
    this.certificateForm = this.fb.group({
      certType: [CertType.ROOT, Validators.required],
      issuerId: [0, Validators.required],
      subject: this.fb.group({
        commonName: ['', Validators.required],
        organization: [''],
        orgUnit: [''],
        country: ['', [Validators.minLength(2), Validators.maxLength(2)]],
        state: [''],
        locality: [''],
      }),
      notBefore: ['', Validators.required],
      notAfter: ['', Validators.required],

      san: this.fb.array([]),
      keyUsage: this.fb.array([]),
      extendedKeyUsage: this.fb.array([]),

      pathLenConstraint: [-1],
    });

    this.certificateForm.get('certType')?.valueChanges.subscribe(type => {
      const issuer = this.certificateForm.get('issuerId');

      if (type === CertType.ROOT) {
        issuer?.clearValidators();
      } else if (type === CertType.INTERMEDIATE) {
        issuer?.setValidators([Validators.required]);
      } else { // END_ENTITY
        issuer?.setValidators([Validators.required]);
      }

      issuer?.updateValueAndValidity();
    });

    this.activatedRoute.url.subscribe({
      next: () => this.reloadCerts()
    })
  }

  //SAN array
  get san() {
    return this.certificateForm.get('san') as FormArray;
  }
  addSan() {
    this.san.push(
      this.fb.group({
        type: ['DNS', Validators.required],
        value: ['', Validators.required],
      })
    );
  }
  removeSan(index: number) {
    this.san.removeAt(index);
  }

  //Key Usage
  get keyUsage() {
    return this.certificateForm.get('keyUsage') as FormArray;
  }
  addKeyUsage() {
    this.keyUsage.push(this.fb.control(''));
  }
  removeKeyUsage(index: number) {
    this.keyUsage.removeAt(index);
  }

  //Extended Key Usage
  get extendedKeyUsage() {
    return this.certificateForm.get('extendedKeyUsage') as FormArray;
  }
  addExtendedKeyUsage() {
    this.extendedKeyUsage.push(this.fb.control(''));
  }
  removeExtendedKeyUsage(index: number) {
    this.extendedKeyUsage.removeAt(index);
  }

  errorMessage: String = "";
  successMessage: String = "";
  submit() {
    if (this.certificateForm.valid) {
      this.certService.createCertificate(this.certificateForm.value).subscribe({
        next: (data) => {this.successMessage = "Success"; this.errorMessage = ""; this.reloadCerts()},
        error: (err) => {this.errorMessage = err.error?.message; this.successMessage = ""; this.cd.detectChanges()}
      });
    }
  }

  onCertSelected(cert: SimpleCertificateDTO){
    this.certificateForm.patchValue({
      issuerId: cert.id
    })
  }
}
