import { Component, EventEmitter, Input, Output, output } from '@angular/core';
import { CardComponent } from "../../Containers/card/card.component";
import { BasicCertificateDataComponent } from "../basic-certificate-data/basic-certificate-data.component";
import { SimpleCertificateDTO } from '../../../DTO/Certificate/SimpleCertificateDTO';
import { CertificateTableComponent } from "../certificate-table/certificate-table.component";

@Component({
  selector: 'app-select-certificate',
  imports: [CertificateTableComponent],
  templateUrl: './select-certificate.html',
  styleUrl: './select-certificate.css'
})
export class SelectCertificate {
  @Input() certData: SimpleCertificateDTO[] = [];
  @Output() onCertSelected = new EventEmitter<SimpleCertificateDTO>();

  emitCert(c: SimpleCertificateDTO){
    this.onCertSelected.emit(c);
  }
}
