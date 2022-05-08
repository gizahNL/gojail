package gojail

import "errors"

//JailCreate creates a Jail with the given parameters, no validation is done atm
//accepted types for interface{}: int32/*int32/uint32/*uint32/string/bool/[]byte
//byte slices MUST be null terminated if the OS expects a string var.
func JailCreate(jailParameters map[string]interface{}) (Jail, error) {
	return jailCreate(jailParameters, JailFlagCreate)
}

//Similar to JailCreate but also attaches to the new jail. This can be used to
//create short-lived nopersist jails to simplify cleanup after the jailed
//process exits
func JailCreateAndAttach(jailParameters map[string]interface{}) (Jail, error) {
	return jailCreate(jailParameters, JailFlagCreate|JailFlagAttach)
}

func jailParametersGetName(parameters map[string]interface{}) (string, error) {
	//not truly mandatory
	if _, ok := parameters["name"]; !ok {
		return "", errors.New("Name param mandatory for jail creation")
	}
	name, ok := parameters["name"].(string)
	if !ok {
		return "", errors.New("Name param must be a string")
	}
	return name, nil
}

func jailCreate(parameters map[string]interface{}, flag int) (*jail, error) {
	name, err := jailParametersGetName(parameters)
	if err != nil {
		return nil, err
	}

	iovecs, err := JailParseParametersToIovec(parameters)
	if err != nil {
		return nil, err
	}

	jailID, err := JailSet(iovecs, flag)
	if err != nil {
		return nil, err
	}
	return &jail{
		jailID:   jailID,
		jailName: name,
	}, nil
}
