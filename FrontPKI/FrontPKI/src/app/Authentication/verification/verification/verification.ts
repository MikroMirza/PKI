import { Component } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { ToastNotifyService } from '../../../common/ToastNotifyService';
import { UserService } from '../../../Services/user.service';

@Component({
  selector: 'app-verification',
  imports: [],
  templateUrl: './verification.html',
  styleUrl: './verification.css'
})
export class Verification {

  constructor(private userService: UserService, private route: ActivatedRoute, 
    private authService: AuthenticationService, private router: Router, 
    private toastNotifyService: ToastNotifyService) {}

  onButtonClick(): void {
    this.route.queryParamMap.subscribe(params => {
      const token: string | null = params.get('token');
      if (token) {
        this.userService.verifyUser(token).subscribe({
          next: (res) => {
            this.authService.logOut();
            this.toastNotifyService.showSuccessful('Successfully verified account.')
            this.router.navigate(['authentication/login']);
          },
          error: (err) => {
            const errorCode = err?.error?.errorCode;
            if (errorCode == 'EXPIRED' || errorCode == 'ALREADY_VERIFIED') {
              this.toastNotifyService.showError('You either already verified your account or time to verify expired.')
            } else {
              this.toastNotifyService.showError('Account verification failed.')
            }
            this.router.navigate(['authentication/login']);
          }
        });
      }
    });
  }
}
