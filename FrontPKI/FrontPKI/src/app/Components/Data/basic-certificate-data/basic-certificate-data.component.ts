import { Component, Input } from '@angular/core';
import { SimpleCertificateDTO } from '../../../DTO/Certificate/SimpleCertificateDTO';
import { MatButtonModule } from '@angular/material/button';
import { CertificateService } from '../../../Services/certificate.service';
import { MatDialog } from '@angular/material/dialog';
import { CertificateInfoDialogComponent } from '../../../dialog/Components/Dialogs/certificate-info-dialog/certificate-info-dialog';

@Component({
  selector: 'app-basic-certificate-data',
  standalone: true,
  imports: [MatButtonModule],
  templateUrl: './basic-certificate-data.component.html',
  styleUrl: './basic-certificate-data.component.css'
})
export class BasicCertificateDataComponent {
  @Input() certData !: SimpleCertificateDTO;

  constructor(
    private certService: CertificateService,
    private dialog: MatDialog
  ){}

  showDetails(){
    this.certService.getCertificateDetails(this.certData.id).subscribe({
      next: (data) => {
        this.dialog.open(CertificateInfoDialogComponent, {
          width: '500px',
          height: '700px',
          data: data
        });
      }
    })
  }
}
