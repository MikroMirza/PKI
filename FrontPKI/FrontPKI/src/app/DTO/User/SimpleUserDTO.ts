import { SimpleCertificateDTO } from "../Certificate/SimpleCertificateDTO";

export class SimpleUserDTO{
    id: number = 0;
    email: String = "";
    certs: SimpleCertificateDTO[] = [];
}