import { StringPair } from "./StringPair";

export class CertificateDetailsDTO{
	details: StringPair[] = [];
	subjectPublicKeyInfo: StringPair[] = [];
	validity: StringPair[] = [];
	extensions: StringPair[] = [];
}