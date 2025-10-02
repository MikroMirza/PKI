import { Component } from '@angular/core';
import { MatDialogRef } from '@angular/material/dialog';
import { FormsModule } from '@angular/forms';
import { CommonModule } from '@angular/common';

import { MatDialogModule } from '@angular/material/dialog';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';

@Component({
  selector: 'app-export-password-dialog',
  standalone: true,
  imports: [
    CommonModule,
    FormsModule,

    MatDialogModule,
    MatFormFieldModule,
    MatInputModule,
    MatButtonModule,
    MatIconModule,
  ],
  templateUrl: './export-password-dialog-component.html',
})
export class ExportPasswordDialogComponent {
  password: string = '';
  confirmPassword: string = '';
  hidePassword = true;
  hideConfirm = true;

  constructor(public dialogRef: MatDialogRef<ExportPasswordDialogComponent>) {}

  onConfirm() {
    if (this.password === this.confirmPassword) {
      this.dialogRef.close(this.password);
    }
  }

  onCancel() {
    this.dialogRef.close(null);
  }
}
