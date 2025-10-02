import { StringPair } from "./StringPair";

export class CertificateDetailsDTO{
	details: StringPair = new StringPair();
	subjectPublicKeyInfo: StringPair = new StringPair();
	validity: StringPair = new StringPair();
	extensions: StringPair = new StringPair();
}