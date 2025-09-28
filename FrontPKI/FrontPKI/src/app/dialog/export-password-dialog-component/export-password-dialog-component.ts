import { Component } from '@angular/core';
import { MatDialogRef } from '@angular/material/dialog';
import { FormsModule } from '@angular/forms';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-export-password-dialog',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './export-password-dialog-component.html'
})
export class ExportPasswordDialogComponent {
  password: string = '';

  constructor(public dialogRef: MatDialogRef<ExportPasswordDialogComponent>) {}

  onConfirm() {
    this.dialogRef.close(this.password);
  }

  onCancel() {
    this.dialogRef.close(null);
  }
}
