import { ChangeDetectorRef, Component } from '@angular/core';
import { Observable } from 'rxjs';
import { SimpleCertificateDTO } from '../../DTO/Certificate/SimpleCertificateDTO';
import { ActivatedRoute, Router, RouterModule } from '@angular/router';
import { CertificateService } from '../../Services/certificate.service';
import { CertificateTableComponent } from "../../Components/certificate-table/certificate-table.component";
import { AsyncPipe } from '@angular/common';
import { CreateCertificateDTO } from '../../DTO/Certificate/CreateIntermediateDTO';
import { FormsModule } from '@angular/forms';

@Component({
  selector: 'app-create-ca-certificate',
  standalone: true,
  imports: [CertificateTableComponent, AsyncPipe, RouterModule, FormsModule],
  templateUrl: './create-ca-certificate.component.html',
  styleUrl: './create-ca-certificate.component.css'
})
export class CreateCaCertificateComponent {

  constructor(
    private route: ActivatedRoute,
    private certService: CertificateService,
    private cd: ChangeDetectorRef
  ){}

  certData$!: Observable<SimpleCertificateDTO[]>;

  issuerId: number = 0;
  cn: String = "";
  org: String = "";
  orgUnit: String = "";
  notBefore: String = "";
  notAfter: String = "";
  maxIntermediate: number = 0;
  isEndEntity: boolean = false;

  errorMessage: String = "";
  successMessage: String = "";

  ngOnInit(){
    this.route.url.subscribe({
      next: (data) => this.loadCerts()
    })
  }

  loadCerts(){
    this.certData$ = this.certService.getCertificates()
    this.cd.detectChanges();
  }

  create(){
    this.errorMessage = ""
    this.successMessage = ""

    let data = new CreateCertificateDTO();
    data.issuerId = this.issuerId;
    data.cn = this.cn;
    data.organization = this.org;
    data.organizationUnit = this.orgUnit;
    data.notBefore = this.notBefore;
    data.notAfter = this.notAfter;
    data.pathLenConstraint = this.maxIntermediate;
    data.isEndEntity = this.isEndEntity;

    this.certService.createIntermediate(data).subscribe({
      error: (err) => this.errorMessage = err?.message,
      next: (res) => {this.successMessage = "SUCCESS!", this.loadCerts()}
    })
  }
}
