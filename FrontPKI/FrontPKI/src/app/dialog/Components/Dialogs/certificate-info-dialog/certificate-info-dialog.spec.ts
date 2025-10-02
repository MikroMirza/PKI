import { ComponentFixture, TestBed } from '@angular/core/testing';

import { CertificateInfoDialog } from './certificate-info-dialog';

describe('CertificateInfoDialog', () => {
  let component: CertificateInfoDialog;
  let fixture: ComponentFixture<CertificateInfoDialog>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [CertificateInfoDialog]
    })
    .compileComponents();

    fixture = TestBed.createComponent(CertificateInfoDialog);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
