import { ComponentFixture, TestBed } from '@angular/core/testing';

import { GenerateCsr } from './generate-csr';

describe('GenerateCsr', () => {
  let component: GenerateCsr;
  let fixture: ComponentFixture<GenerateCsr>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [GenerateCsr]
    })
    .compileComponents();

    fixture = TestBed.createComponent(GenerateCsr);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
