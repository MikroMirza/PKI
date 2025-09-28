import { CommonModule } from '@angular/common';
import { Component, EventEmitter, Input, Output } from '@angular/core';
import { SimpleCertificateDTO } from '../../../DTO/Certificate/SimpleCertificateDTO';
import { CardComponent } from "../../Containers/card/card.component";
import { BasicCertificateDataComponent } from "../basic-certificate-data/basic-certificate-data.component";

@Component({
  selector: 'app-certificate-table',
  standalone: true,
  imports: [CommonModule, CardComponent, BasicCertificateDataComponent],
  templateUrl: './certificate-table.component.html',
  styleUrls: ['./certificate-table.component.css']
})
export class CertificateTableComponent {
  @Input() certData: SimpleCertificateDTO[] = [];
  @Output() certSelected = new EventEmitter<SimpleCertificateDTO>();

  selectedCert?: SimpleCertificateDTO;

  selectRow(cert: SimpleCertificateDTO) {
    this.selectedCert = cert;
    this.certSelected.emit(cert);
  }
}
