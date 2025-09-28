import { ComponentFixture, TestBed } from '@angular/core/testing';

import { SelectCertificate } from './select-certificate';

describe('SelectCertificate', () => {
  let component: SelectCertificate;
  let fixture: ComponentFixture<SelectCertificate>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [SelectCertificate]
    })
    .compileComponents();

    fixture = TestBed.createComponent(SelectCertificate);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
