import { ComponentFixture, TestBed } from '@angular/core/testing';

import { ExportPasswordDialogComponent } from './export-password-dialog-component';

describe('ExportPasswordDialogComponent', () => {
  let component: ExportPasswordDialogComponent;
  let fixture: ComponentFixture<ExportPasswordDialogComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [ExportPasswordDialogComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(ExportPasswordDialogComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
