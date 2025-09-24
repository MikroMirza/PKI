import { CommonModule } from '@angular/common';
import { Component } from '@angular/core';
import { FormArray, FormBuilder, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms';

@Component({
  selector: 'app-generate-certificate',
  standalone: true,
  imports: [ReactiveFormsModule, CommonModule],
  templateUrl: './generate-certificate.component.html',
  styleUrl: './generate-certificate.component.css'
})
export class GenerateCertificateComponent {
  certificateForm!: FormGroup;

  constructor(private fb: FormBuilder) {}

  ngOnInit(): void {
    this.certificateForm = this.fb.group({
      issuerId: [0, Validators.required],
      subject: this.fb.group({
        commonName: ['', Validators.required],
        organization: [''],
        orgUnit: [''],
        country: [''],
        state: [''],
        locality: [''],
      }),
      notBefore: ['', Validators.required],
      notAfter: ['', Validators.required],

      san: this.fb.array([]), // ✅ now holds objects { type, value }
      keyUsage: this.fb.array([]),
      extendedKeyUsage: this.fb.array([]),

      isEndEntity: [false],
      pathLenConstraint: [-1],
    });
  }

  // --- SAN array ---
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

  // --- Key Usage ---
  get keyUsage() {
    return this.certificateForm.get('keyUsage') as FormArray;
  }
  addKeyUsage() {
    this.keyUsage.push(this.fb.control(''));
  }
  removeKeyUsage(index: number) {
    this.keyUsage.removeAt(index);
  }

  // --- Extended Key Usage ---
  get extendedKeyUsage() {
    return this.certificateForm.get('extendedKeyUsage') as FormArray;
  }
  addExtendedKeyUsage() {
    this.extendedKeyUsage.push(this.fb.control(''));
  }
  removeExtendedKeyUsage(index: number) {
    this.extendedKeyUsage.removeAt(index);
  }

  submit() {
    if (this.certificateForm.valid) {
      console.log(this.certificateForm.value);
      // this.certificateForm.value matches CreateCertificateDTO
    }
  }
}
