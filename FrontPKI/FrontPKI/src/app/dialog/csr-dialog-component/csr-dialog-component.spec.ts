import { ComponentFixture, TestBed } from '@angular/core/testing';

import { CsrDialogComponent } from './csr-dialog-component';

describe('CsrDialogComponent', () => {
  let component: CsrDialogComponent;
  let fixture: ComponentFixture<CsrDialogComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [CsrDialogComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(CsrDialogComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
