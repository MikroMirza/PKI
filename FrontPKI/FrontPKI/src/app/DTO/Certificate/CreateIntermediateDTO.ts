export class CreateCertificateDTO{
	issuerId: number = 0;
	cn: String = "";
	organization: String = "";
	organizationUnit: String = "";
	notBefore: String = "";
	notAfter: String = "";
	pathLenConstraint: number = 0;
	isEndEntity: boolean = false;
}