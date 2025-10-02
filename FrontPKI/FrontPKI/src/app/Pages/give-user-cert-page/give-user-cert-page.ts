import { ChangeDetectorRef, Component } from '@angular/core';
import { MatSelectModule } from '@angular/material/select';
import { SimpleUserDTO } from '../../DTO/User/SimpleUserDTO';
import { UserService } from '../../Services/user.service';
import { ActivatedRoute } from '@angular/router';
import { CommonModule } from '@angular/common';
import { SelectCertificate } from "../../Components/Data/select-certificate/select-certificate";
import { SimpleCertificateDTO } from '../../DTO/Certificate/SimpleCertificateDTO';
import { CertificateService } from '../../Services/certificate.service';
import { MatButtonModule } from '@angular/material/button';
import { MatExpansionModule } from '@angular/material/expansion';

@Component({
  selector: 'app-give-user-cert-page',
  imports: [MatSelectModule, CommonModule, SelectCertificate, MatButtonModule, MatExpansionModule],
  templateUrl: './give-user-cert-page.html',
  styleUrl: './give-user-cert-page.css'
})
export class GiveUserCertPage {

  userList: SimpleUserDTO[] = [];
  selectedUserId: number | null = null;
  selected: SimpleUserDTO | null = null;

  allCerts: SimpleCertificateDTO[] = [];
  selectedAllCert: SimpleCertificateDTO | null = null;

  selectedUserCert: SimpleCertificateDTO | null = null;

  constructor(
    private userService: UserService,
    private certService: CertificateService,
    private activatedRoute: ActivatedRoute,
    private cd: ChangeDetectorRef
  ){}

  availableCertSelected(c: SimpleCertificateDTO){
    this.selectedAllCert = c;
  }

  addClicked(){
    if(this.selected == null || this.selectedAllCert == null)
      return;

    this.userService.giveUserCertificate(this.selected?.id, this.selectedAllCert?.id).subscribe({
      complete: () => {this.reloadData(); this.selectedAllCert = null}
    })
  }

  userCertSelected(c: SimpleCertificateDTO){
    this.selectedUserCert = c;
  }

  removeClicked(){
    if(this.selected == null || this.selectedUserCert == null)
      return;

    this.userService.removeUsersCertificate(this.selected?.id, this.selectedUserCert?.id).subscribe({
      complete: () => {this.reloadData(); this.selectedUserCert = null}
    })
  }

  reloadSelectedUser(){
    console.log("Reload user")

    this.selected = null;
    if(this.selectedUserId == null)
      return

    this.userService.getUser(this.selectedUserId).subscribe({
      next: (data) => {
        this.selected = data;
        this.cd.detectChanges();
      }
    })
  }

  userChanged(){
    this.reloadSelectedUser()
  }

  reloadData(){
    this.userService.getUsers().subscribe({
      next: (data) => {
        this.userList=data;
        this.cd.detectChanges()
        if(this.selectedUserId != null)
          this.reloadSelectedUser()
      }
    })
    this.certService.getAvailableCertificates().subscribe({
      next: (data) => {this.allCerts=data; this.cd.detectChanges()}
    })
  }

  ngOnInit(){
    this.activatedRoute.url.subscribe({
      next: () => {
        this.reloadData();
      }
    })
  }
}
