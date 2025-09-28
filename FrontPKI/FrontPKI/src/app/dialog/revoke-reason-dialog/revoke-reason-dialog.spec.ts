import { ComponentFixture, TestBed } from '@angular/core/testing';

import { RevokeReasonDialog } from './revoke-reason-dialog';

describe('RevokeReasonDialog', () => {
  let component: RevokeReasonDialog;
  let fixture: ComponentFixture<RevokeReasonDialog>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [RevokeReasonDialog]
    })
    .compileComponents();

    fixture = TestBed.createComponent(RevokeReasonDialog);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
