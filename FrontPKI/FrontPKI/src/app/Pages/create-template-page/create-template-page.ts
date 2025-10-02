import { CommonModule } from '@angular/common';
import { Component } from '@angular/core';
import { FormBuilder, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { MatCheckboxModule } from '@angular/material/checkbox';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatListModule } from '@angular/material/list';
import { SelectCertificate } from "../../Components/Data/select-certificate/select-certificate";
import { CertificateService } from '../../Services/certificate.service';
import { Observable } from 'rxjs';
import { SimpleCertificateDTO } from '../../DTO/Certificate/SimpleCertificateDTO';
import { TemplateService } from '../../Services/template.service';
import { TemplateDTO } from '../../DTO/Certificate/TemplateDTO';

@Component({
  selector: 'app-create-template-page',
  imports: [MatCheckboxModule, MatFormFieldModule, ReactiveFormsModule, CommonModule, MatListModule, MatInputModule, MatButtonModule, SelectCertificate],
  templateUrl: './create-template-page.html',
  styleUrl: './create-template-page.css'
})
export class CreateTemplatePage {
  templateForm: FormGroup;

  sanTypes = [
    { name: 'DNS', control: 'dnsRegex' },
    { name: 'IP', control: 'ipRegex' },
    { name: 'URI', control: 'uriRegex' },
    { name: 'Email', control: 'emailRegex' }
  ];

  keyUsageOptions = [
    'digitalSignature', 'nonRepudiation', 'keyEncipherment',
    'dataEncipherment', 'keyAgreement', 'keyCertSign', 'cRLSign'
  ];

  extKeyUsageOptions = [
    'serverAuth', 'clientAuth', 'codeSigning',
    'emailProtection', 'timeStamping'
  ];

  certData: Observable<SimpleCertificateDTO[]> = new Observable();
  selectedCert: SimpleCertificateDTO | null = null;


  onCertSelected(cert: SimpleCertificateDTO){
    this.selectedCert = cert;
  }

  constructor(
    private fb: FormBuilder,
    private certService: CertificateService,
    private templateService: TemplateService
  ) {
    this.certData = certService.getAvailableCACertificates()

    this.templateForm = this.fb.group({
      templateName: ['', Validators.required],
      certId: [0, Validators.required],
      cnRegex: [''],

      // SAN section
      dnsEnabled: [false],
      dnsRegex: [{ value: '', disabled: true }],
      ipEnabled: [false],
      ipRegex: [{ value: '', disabled: true }],
      uriEnabled: [false],
      uriRegex: [{ value: '', disabled: true }],
      emailEnabled: [false],
      emailRegex: [{ value: '', disabled: true }],

      keyUsages: [[]],
      extKeyUsages: [[]],

      ttl: [0]
    });

    // Enable/disable regex inputs dynamically
    this.sanTypes.forEach(type => {
      this.templateForm.get(type.control.replace('Regex', 'Enabled'))?.valueChanges.subscribe(enabled => {
        const regexControl = this.templateForm.get(type.control);
        if (enabled) {
          regexControl?.enable();
        } else {
          regexControl?.disable();
          regexControl?.reset('');
        }
      });
    });
  }

  onCheckboxChange(event: any, controlName: string) {
    const selected = this.templateForm.get(controlName)?.value as string[];
    if (event.checked) {
      this.templateForm.get(controlName)?.setValue([...selected, event.source.value]);
    } else {
      this.templateForm.get(controlName)?.setValue(selected.filter((x: string) => x !== event.source.value));
    }
  }

  onSubmit() {
    if (this.templateForm.valid) {
      const formValue = this.templateForm.value;
      if(this.selectedCert == null)
        return

      console.log(formValue)

      // Convert into DTO format
      const dto: TemplateDTO = {
        id: 0,
        templateName: formValue.templateName,
        certId: this.selectedCert?.id,
        cnRegex: formValue.cnRegex,
        allowedTypes: this.sanTypes
          .filter(t => formValue[t.control.replace('Regex', 'Enabled')])
          .map(t => t.name.toLowerCase()),
        dnsRegex: formValue.dnsRegex,
        ipRegex: formValue.ipRegex,
        uriRegex: formValue.uriRegex,
        emailRegex: formValue.emailRegex,
        keyUsages: formValue.keyUsages,
        extKeyUsages: formValue.extKeyUsages,
        ttl: formValue.ttl
      };

      this.templateService.createTemplate(dto).subscribe({
        next: () => alert("Success"),
        error: () => alert("Error")
      })
    }
  }
}
