import { ComponentFixture, TestBed } from '@angular/core/testing';

import { GiveUserCertPage } from './give-user-cert-page';

describe('GiveUserCertPage', () => {
  let component: GiveUserCertPage;
  let fixture: ComponentFixture<GiveUserCertPage>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [GiveUserCertPage]
    })
    .compileComponents();

    fixture = TestBed.createComponent(GiveUserCertPage);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
