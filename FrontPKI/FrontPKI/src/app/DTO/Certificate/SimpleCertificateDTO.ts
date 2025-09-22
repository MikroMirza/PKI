export class SimpleCertificateDTO{
	id: number = 0;
	subjectCN: string = "";
	subjectO: string = "";
	subjectOU: string = "";
	issuerCN: string = "";
	issuerO: string = "";
	issuerOU: string = "";
	publicKey: string = "";
    notBefore: string = "";
    notAfter: string = "";
	isEndEntity: boolean = false;
	pathLen: number = -1;
}