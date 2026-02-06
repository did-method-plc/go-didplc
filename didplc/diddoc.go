package didplc

type DocVerificationMethod struct {
	ID                 string `json:"id"`
	Type               string `json:"type"`
	Controller         string `json:"controller"`
	PublicKeyMultibase string `json:"publicKeyMultibase"`
}

type DocService struct {
	ID              string `json:"id"`
	Type            string `json:"type"`
	ServiceEndpoint string `json:"serviceEndpoint"`
}

// Struct representing a complete DID document, with the fields relevant to DID PLC.
type Doc struct {
	ID                 string                  `json:"id"`
	AlsoKnownAs        []string                `json:"alsoKnownAs"`
	VerificationMethod []DocVerificationMethod `json:"verificationMethod"`
	Service            []DocService            `json:"service"`
}
