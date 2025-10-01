export class TemplateDTO{
	templateName: String = "";
	certId: Number = 0;
	
	//Empty or null values are ignored
	cnRegex: String = "";
	
	//SAN
	//What SAN types are available
	allowedTypes: String[] = [];
	//The regex for each SAN type
	//If empty or null, anything is allowed
	dnsRegex: String = "";
	ipRegex: String = "";
	uriRegex: String = "";
	emailRegex: String = "";
	
	//Key usage
	keyUsages: String[] = [];
	
	//Extended key usage
	extKeyUsages: String[] = [];
	
	//TTL in days
	//if 0 ignore it
	ttl: Number = 0;
}