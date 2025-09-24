import { CommonModule } from '@angular/common';
import { Component, Input } from '@angular/core';
import { SimpleCertificateDTO } from '../../../DTO/Certificate/SimpleCertificateDTO';
import { CardComponent } from "../../Containers/card/card.component";
import { BasicCertificateDataComponent } from "../basic-certificate-data/basic-certificate-data.component";

@Component({
  selector: 'app-certificate-table',
  standalone: true,
  imports: [CommonModule, CardComponent, BasicCertificateDataComponent],
  templateUrl: './certificate-table.component.html',
  styleUrl: './certificate-table.component.css'
})
export class CertificateTableComponent {
  @Input() certData: SimpleCertificateDTO[] = [];
}
