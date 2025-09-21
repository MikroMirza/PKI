import { Injectable } from "@angular/core";
import { MatSnackBar } from "@angular/material/snack-bar";

@Injectable({
    providedIn: 'root'
})
export class ToastNotifyService {
    success(message: string): void {
        this.snackBar.open(message, 'OK', {
          duration: 3000,
          panelClass: ['toast-success']
        });
      }

    error(message: string): void {
      this.snackBar.open(message, 'Close', {
        duration: 3000,
        panelClass: ['toast-error']
      });
    }

    warning(message: string): void {
      this.snackBar.open(message, 'Close', {
        duration: 3000,
        panelClass: ['toast-warning']
      });
    }
    constructor(private snackBar: MatSnackBar) {}

    showSuccessful(message: string) {
        this.snackBar.open(message, 'Close', {
            duration: 3000,
            panelClass: ['toast-successful']
        });
    }

    showError(message: string) {
        this.snackBar.open(message, 'Close', {
            duration: 3000,
            panelClass: ['toast-error']
        });
    }
}