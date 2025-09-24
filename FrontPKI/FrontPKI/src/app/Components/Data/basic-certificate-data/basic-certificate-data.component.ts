import { Component, Input } from '@angular/core';
import { SimpleCertificateDTO } from '../../../DTO/Certificate/SimpleCertificateDTO';

@Component({
  selector: 'app-basic-certificate-data',
  standalone: true,
  imports: [],
  templateUrl: './basic-certificate-data.component.html',
  styleUrl: './basic-certificate-data.component.css'
})
export class BasicCertificateDataComponent {
  @Input() certData !: SimpleCertificateDTO;
}
