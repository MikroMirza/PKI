import { ComponentFixture, TestBed } from '@angular/core/testing';

import { BasicCertificateDataComponent } from './basic-certificate-data.component';

describe('BasicCertificateDataComponent', () => {
  let component: BasicCertificateDataComponent;
  let fixture: ComponentFixture<BasicCertificateDataComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [BasicCertificateDataComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(BasicCertificateDataComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
