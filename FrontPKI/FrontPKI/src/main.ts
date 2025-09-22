import { bootstrapApplication } from '@angular/platform-browser';
import { provideRouter } from '@angular/router';
import { routes } from './app/app.routes';
import { AppComponent } from './app/Components/app/app.component';
import { appConfig } from './app/app.config';

bootstrapApplication(AppComponent, appConfig);
