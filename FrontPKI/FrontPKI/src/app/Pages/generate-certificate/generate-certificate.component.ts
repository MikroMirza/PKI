import { CommonModule } from '@angular/common';
import { ChangeDetectorRef, Component } from '@angular/core';
import { AbstractControl, FormArray, FormBuilder, FormGroup, ReactiveFormsModule, ValidationErrors, ValidatorFn, Validators } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { MatCheckboxModule } from '@angular/material/checkbox';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { CertType } from '../../common/CertType';
import { SelectCertificate } from "../../Components/Data/select-certificate/select-certificate";
import { ActivatedRoute, Router } from '@angular/router';
import { CertificateService } from '../../Services/certificate.service';
import { Observable } from 'rxjs';
import { SimpleCertificateDTO } from '../../DTO/Certificate/SimpleCertificateDTO';
import { MatListModule } from '@angular/material/list';
import { TemplateDTO } from '../../DTO/Certificate/TemplateDTO';
import { TemplateService } from '../../Services/template.service';
import { MatDialog } from '@angular/material/dialog';
import { TemplateDialog } from '../../dialog/Components/Dialogs/template-dialog/template-dialog';

function validityValidator(maxDays: Number): ValidatorFn {
  return (control: AbstractControl): ValidationErrors | null => {
    const notBefore = new Date(control.get('notBefore')?.value);
    const notAfter = new Date(control.get('notAfter')?.value);

    const diffDays = (notAfter.getTime() - notBefore.getTime()) / (1000 * 60 * 60 * 24);
    if (Math.abs(diffDays) > maxDays.valueOf()) {
      return { tooLong: true };
    }

    return null;
  };
}

@Component({
  selector: 'app-generate-certificate',
  standalone: true,
  imports: [
    ReactiveFormsModule,
    CommonModule,
    MatIconModule,
    MatSelectModule,
    MatButtonModule, 
    MatCheckboxModule,
    MatInputModule,
    MatFormFieldModule,
    SelectCertificate,
    MatListModule
  ],
  templateUrl: './generate-certificate.component.html',
  styleUrl: './generate-certificate.component.css'
})
export class GenerateCertificateComponent {
  issuerId: number = 0
  templates: TemplateDTO[] = []

  certificateForm!: FormGroup;
  certTypes = ['ROOT', 'INTERMEDIATE', 'END_ENTITY']
  certData: Observable<SimpleCertificateDTO[]> = new Observable<SimpleCertificateDTO[]>();

  keyUsageOptions = [
    'digitalSignature', 'nonRepudiation', 'keyEncipherment',
    'dataEncipherment', 'keyAgreement', 'keyCertSign', 'cRLSign'
  ];

  extKeyUsageOptions = [
    'serverAuth', 'clientAuth', 'codeSigning',
    'emailProtection', 'timeStamping'
  ];

  constructor(
    private fb: FormBuilder,
    private activatedRoute: ActivatedRoute,
    private certService: CertificateService,
    private tempService: TemplateService,
    private router: Router,
    private cd: ChangeDetectorRef,
  private dialog: MatDialog) {}


    showTemplateDetails(){
      const dialogRef = this.dialog.open(TemplateDialog, {
        width: '300px',
        data: this.selectedTemplate
      });
    }

  selectedTemplate: TemplateDTO | null = null;
  tempSelectChanged(){
    let tempId: number = this.certificateForm.get("templateId")?.value;

    if(tempId == 0){
      this.selectedTemplate = null;
      this.setValidators();
      this.cd.detectChanges();
      return;
    }

    this.tempService.getTemplate(tempId).subscribe({
      next: (data) => {
        this.selectedTemplate = data;
        this.setValidators();
        this.cd.detectChanges();
      }
    })
  }

  reloadCerts(){
    this.certData = this.certService.getAvailableCACertificates();
    this.cd.detectChanges();
  }

  ngOnInit(): void {
    this.certificateForm = this.fb.group({
      certType: [CertType.ROOT, Validators.required],
      issuerId: [0, Validators.required],
      templateId: 0,
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
      keyUsage: [[]],
      extendedKeyUsage: [[]],

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

  allowedSANTypes: String[] = ['DNS', 'IP', 'EMAIL', 'URI'];
  setValidators(){
    this.certificateForm.clearValidators();
    if (this.selectedTemplate != null){
      let temp: TemplateDTO = this.selectedTemplate;

      if(temp.cnRegex != null && temp.cnRegex != "")
        this.certificateForm.get("subject")?.get("commonName")?.setValidators([Validators.required, Validators.pattern(temp.cnRegex.toString())])
      this.certificateForm.get("subject")?.get("commonName")?.updateValueAndValidity()

      this.san.clear()
      this.allowedSANTypes = temp.allowedTypes.map(s => s.toUpperCase());

      if(temp.ttl.valueOf() > 0)
        this.certificateForm.addValidators(validityValidator(temp.ttl));
      this.certificateForm.updateValueAndValidity();

      this.certificateForm.get("keyUsage")?.setValue(temp.keyUsages);
      this.certificateForm.get("extendedKeyUsage")?.setValue(temp.extKeyUsages);

      return
    }

    this.certificateForm.get("subject")?.get("commonName")?.setValidators([Validators.required])
    this.certificateForm.get("subject")?.get("commonName")?.updateValueAndValidity()
    this.allowedSANTypes = ['DNS', 'IP', 'EMAIL', 'URI'];
    this.certificateForm.updateValueAndValidity();
  }
  
  sanSelectChanged(index: number) {
    const sanGroup = this.san.at(index) as FormGroup;
    const type = sanGroup.get('type')?.value;
    const valueControl = sanGroup.get('value');

    if (!valueControl) return;

    valueControl.setValidators([Validators.required]);

    let temp: TemplateDTO | null = this.selectedTemplate;

    if(temp != null)
      switch (type.toUpperCase()) {
        case 'DNS':
          if(type.dnsRegex != "")
            valueControl.setValidators([
              Validators.required,
              Validators.pattern(temp.dnsRegex.toString())
            ]);
            console.log("gas")
          break;

        case 'IP':
          if(temp.ipRegex != "")
            valueControl.setValidators([
              Validators.required,
              Validators.pattern(temp.ipRegex.toString())
            ]);
          break;

        case 'EMAIL':
          if(temp.emailRegex != "")
            valueControl.setValidators([
              Validators.required,
              Validators.pattern(temp.emailRegex.toString())
            ]);
          break;
          
        case 'URI':
          if(temp.uriRegex != "")
            valueControl.setValidators([
              Validators.required,
              Validators.pattern(temp.uriRegex.toString())
            ]);
          break;
      }
    valueControl.updateValueAndValidity()
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

    this.sanSelectChanged(this.san.length - 1)
  }
  removeSan(index: number) {
    this.san.removeAt(index);
  }

  errorMessage: String = "";
  successMessage: String = "";
  submit() {
    if (this.certificateForm.valid) {
      this.certService.createCertificate(this.certificateForm.value).subscribe({
        next: (data) => {alert("Success"); this.router.navigate(["/mainpage"]); this.reloadCerts()},
        error: (err) => {this.errorMessage = err.error?.message; this.successMessage = ""; this.cd.detectChanges()}
      });
    }
  }

  selectedTempId: number = 0;

  onCertSelected(cert: SimpleCertificateDTO){
    this.issuerId = cert.id;
    this.certificateForm.patchValue({
      issuerId: cert.id
    })
    this.certService.getCertificateTemplates(this.issuerId).subscribe({
      next: (data) => {
        this.templates = data;
        this.cd.detectChanges();
      }
    })
    this.selectedTempId = 0;
    this.certificateForm.patchValue({
      'templateId': 0
    })
    this.tempSelectChanged();
  }
}
