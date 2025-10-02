import { Component, Inject } from '@angular/core';
import { MAT_DIALOG_DATA, MatDialogRef } from '@angular/material/dialog';
import { TemplateDTO } from '../../../../DTO/Certificate/TemplateDTO';
import { CommonModule } from '@angular/common';
import { MatTabsModule } from '@angular/material/tabs';
import { MatButtonModule } from '@angular/material/button';

@Component({
  selector: 'app-template-dialog',
  imports: [CommonModule, MatTabsModule, MatButtonModule],
  templateUrl: './template-dialog.html',
  styleUrl: './template-dialog.css'
})
export class TemplateDialog {
  constructor(
    public dialogRef: MatDialogRef<TemplateDialog>,
    @Inject(MAT_DIALOG_DATA) public templateDetails: TemplateDTO
  ) {}

  
  close() {
    this.dialogRef.close();
  }
}
