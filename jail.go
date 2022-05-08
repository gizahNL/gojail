package gojail

import (
	"errors"
	"syscall"
)

//Jail interface to interact with jails
type Jail interface {
	//Name returns the jail name
	Name() string
	//ID returns the jail ID
	ID() JailID
	//Attach attaches the current running process to the jailq
	Attach() error
	//RunIn runs a command inside the jail
	RunIn() error
	//Destroy kills all running commands in a jail and removes it from the system
	Destroy() error
	//CreateChildJail creates a Jail as a child in the current jail, incrementing max children as needed
	CreateChildJail(map[string]interface{}) (Jail, error)
	//Set jail parameters
	Set(map[string]interface{}) error
}

type jail struct {
	jailID   JailID
	jailName string
}

func (j *jail) Name() string {
	return j.jailName
}

func (j *jail) ID() JailID {
	return j.jailID
}

func (j *jail) Attach() error {
	return jailJidSyscall(syscall.SYS_JAIL_ATTACH, j.jailID)
}

func (j *jail) Destroy() error {
	return jailJidSyscall(syscall.SYS_JAIL_REMOVE, j.jailID)
}

func (j *jail) RunIn() error {
	return errors.New("Not implemented")
}

func (j *jail) Set(params map[string]interface{}) error {
	params["jid"] = j.ID()
	iov, err := JailParseParametersToIovec(params)
	if err != nil {
		return err
	}
	_, err = JailSet(iov, JailFlagUpdate)
	return err
}
