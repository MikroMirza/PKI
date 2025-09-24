import { SubjectDTO } from "./SubjectDTO";
import { TypeValue } from "./TypeValue";

export class CreateCertificateDTO{
	//The certificate data
	issuerId: number = 0;
	subject: SubjectDTO = new SubjectDTO();
	notBefore: String = "";
	notAfter: String = "";
	
	//EXTENSIONS
	//SAN
	san: TypeValue[] = [];
	
	//KeyUsage
	keyUsage: String[] = [];
	
	//ExtendedKeyUsage
	extendedKeyUsage: String[] = [];
	
	//BasicConstraints
	isEndEntity: Boolean = false;
	pathLenConstraint: number = -1;
}