import { ComponentFixture, TestBed } from '@angular/core/testing';

import { CreateCaCertificateComponent } from './create-ca-certificate.component';

describe('CreateCaCertificateComponent', () => {
  let component: CreateCaCertificateComponent;
  let fixture: ComponentFixture<CreateCaCertificateComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [CreateCaCertificateComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(CreateCaCertificateComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
