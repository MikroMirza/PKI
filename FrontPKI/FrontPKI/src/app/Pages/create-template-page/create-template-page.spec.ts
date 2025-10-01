import { ComponentFixture, TestBed } from '@angular/core/testing';

import { CreateTemplatePage } from './create-template-page';

describe('CreateTemplatePage', () => {
  let component: CreateTemplatePage;
  let fixture: ComponentFixture<CreateTemplatePage>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [CreateTemplatePage]
    })
    .compileComponents();

    fixture = TestBed.createComponent(CreateTemplatePage);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
