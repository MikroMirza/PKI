import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { ToastNotifyService } from '../../../common/ToastNotifyService';
import { UserService } from '../../../Services/user.service';
import { CommonModule } from '@angular/common';
@Component({
  selector: 'app-verification',
  imports: [CommonModule],
  templateUrl: './verification.html',
  styleUrls: ['./verification.css']
})
export class Verification implements OnInit {
  verified: boolean | null = null; 

  constructor(
    private userService: UserService,
    private route: ActivatedRoute,
    private router: Router,
    private toastNotifyService: ToastNotifyService
  ) {}

  ngOnInit(): void {
    this.route.queryParamMap.subscribe(params => {
      const token = params.get('token');
      if (!token) {
        this.toastNotifyService.showError('Invalid verification link.');
        this.verified = false;
        return;
      }

      this.userService.verifyUser(token).subscribe({
        next: () => {
          this.toastNotifyService.showSuccessful('Successfully verified account.');
          this.verified = true;
          setTimeout(() => this.router.navigate(['']), 2000);
        },
        error: (err) => {
          const backendMsg = err?.error?.message || 'Account verification failed.';
          this.toastNotifyService.showError(backendMsg);
          this.verified = false;
          setTimeout(() => this.router.navigate(['']), 2000);
        }
      });
    });
  }
}
