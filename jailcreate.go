package gojail

//JailCreate creates a Jail with the given parameters, no validation is done atm
//accepted types for interface{}: int32/*int32/uint32/*uint32/string/bool/[]byte
//byte slices MUST be null terminated if the OS expects a string var.
func JailCreate(jailParameters map[string]interface{}) (Jail, error) {
	return jailCreate(jailParameters)
}
