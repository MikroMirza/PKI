import { CommonModule } from '@angular/common';
import { Component, Input } from '@angular/core';
import { SimpleCertificateDTO } from '../../DTO/Certificate/SimpleCertificateDTO';

@Component({
  selector: 'app-certificate-table',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './certificate-table.component.html',
  styleUrl: './certificate-table.component.css'
})
export class CertificateTableComponent {
  @Input() certData: SimpleCertificateDTO[] = [];
}
