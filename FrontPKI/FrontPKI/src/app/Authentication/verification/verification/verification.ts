import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { ToastNotifyService } from '../../../common/ToastNotifyService';
import { UserService } from '../../../Services/user.service';

@Component({
  selector: 'app-verification',
  templateUrl: './verification.html',
  styleUrls: ['./verification.css']
})
export class Verification implements OnInit {

  constructor(
    private userService: UserService,
    private route: ActivatedRoute,
    private router: Router,
    private toastNotifyService: ToastNotifyService
  ) {}
  ngOnInit(): void {
    throw new Error('Method not implemented.');
  }

  onButtonClick(): void {
    this.route.queryParamMap.subscribe(params => {
      const token = params.get('token');
      if (!token) {
        this.toastNotifyService.showError('Invalid verification link.');
        this.router.navigate(['']); 
        return;
      }

      this.userService.verifyUser(token).subscribe({
        next: () => {
          this.toastNotifyService.showSuccessful('Successfully verified account.');
          this.router.navigate(['']);
        },
        error: (err) => {
          const backendMsg = err?.error?.message || 'Account verification failed.';
          this.toastNotifyService.showError(backendMsg);
          this.router.navigate(['']);
        }
      });
    });
  }
}
