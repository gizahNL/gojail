package gojail

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"syscall"
	"unsafe"
)

const (
	//syscall flags
	jailFlagCreate = 0x01
	jailFlagUpdate = 0x02
	jailFlagAttach = 0x04
	jailFlagDying  = 0x08

	maxhostnamelen = 256
	errormsglen    = 1024
)

var (
	iovName   = []byte("name\000")
	iovJid    = []byte("jid\000")
	iovErrmsg = []byte("errmsg\000")
)

//Jail interface to interact with jails
type Jail interface {
	//Name returns the jail name
	Name() string
	//ID returns the jail ID
	ID() int
	//Attach attaches the current running process to the jail
	Attach() error
	//RunIn runs a command inside the jail
	RunIn() error
	//Destroy kills all running commands in a jail and removes it from the system
	Destroy() error
	//CreateChildJail creates a Jail as a child in the current jail, incrementing max children as needed
	CreateChildJail(map[string]interface{}) (Jail, error)
}

type jail struct {
	jailID   int
	jailName string
}

func paramToIOVec(key string, value interface{}) ([]syscall.Iovec, error) {
	var val *byte
	var valsize int
	name := []byte(key + "\000")

	switch v := value.(type) {
	case int32:
		i := value.(int32)
		val = (*byte)(unsafe.Pointer(&i))
		valsize = 4
	case uint32:
		i := value.(uint32)
		val = (*byte)(unsafe.Pointer(&i))
		valsize = 4
	case *int32:
		i := value.(*int32)
		val = (*byte)(unsafe.Pointer(i))
		valsize = 4
	case *uint32:
		i := value.(*uint32)
		val = (*byte)(unsafe.Pointer(i))
		valsize = 4
	case string:
		i := value.(string)
		buf := []byte(i + "\000")
		val = &buf[0]
		valsize = len(buf)
	case []byte:
		i := value.([]byte)
		val = &i[0]
		valsize = len(v)
	case bool:
		i := value.(bool)
		if !i && !strings.HasPrefix(key, "no") {
			name = []byte("no" + key + "\000")
		} else if i && strings.HasPrefix(key, "no") {
			name = []byte(strings.TrimPrefix(key, "no"))
		}
		val = nil
		valsize = 0
	default:
		return nil, fmt.Errorf("paramToIOVec: type: %s not implemented", reflect.TypeOf(v))
	}
	return makeJailIovec(name, val, valsize), nil
}

func makeJailIovec(name []byte, value *byte, valuesize int) []syscall.Iovec {
	iovecs := make([]syscall.Iovec, 2)

	iovecs[0].Base = &name[0]
	iovecs[0].SetLen(len(name))

	iovecs[1].Base = value
	iovecs[1].SetLen(valuesize)
	return iovecs
}

func makeErrorIov() ([]byte, []syscall.Iovec) {
	errmsg := make([]byte, errormsglen)
	erriov := makeJailIovec(iovErrmsg, &errmsg[0], len(errmsg))
	return errmsg, erriov
}

func jailIOVSyscall(callnum uintptr, iovecs []syscall.Iovec, flags int) (int, error) {
	errbuf, erriov := makeErrorIov()

	iovecs = append(iovecs, erriov...)

	jid, _, errno := syscall.Syscall(callnum, uintptr(unsafe.Pointer(&iovecs[0])), uintptr(len(iovecs)), uintptr(flags))
	if int(jid) == -1 || errno != 0 {
		if errbuf[0] == 0 {
			return int(jid), errno
		}
		return int(jid), errors.New(string(errbuf))
	}
	return int(jid), nil
}

func jailJidSyscall(callnum uintptr, jid int) error {
	_, _, errno := syscall.Syscall(callnum, uintptr(jid), 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func jailGet(iovecs []syscall.Iovec, flags int) (int, error) {
	return jailIOVSyscall(syscall.SYS_JAIL_GET, iovecs, flags)
}

func jailSet(iovecs []syscall.Iovec, flags int) (int, error) {
	return jailIOVSyscall(syscall.SYS_JAIL_SET, iovecs, flags)
}

//JailGetByName queries the OS for Jail with name jailName
func JailGetByName(jailName string) (Jail, error) {
	JailName := []byte(jailName + "\000")
	iov := makeJailIovec(iovName, &JailName[0], len(JailName))

	jid, err := jailGet(iov, 0)
	if err != nil {
		return nil, err
	}
	return &jail{
		jailID:   jid,
		jailName: jailName,
	}, nil
}

//JailGetByID queries the OS for Jail with jid jailID
func JailGetByID(jailID int) (Jail, error) {
	namebuf := make([]byte, maxhostnamelen)
	jid := int32(jailID)
	iovecs := makeJailIovec(iovJid, (*byte)(unsafe.Pointer(&jid)), 4)
	iovecs = append(iovecs, makeJailIovec(iovName, &namebuf[0], len(namebuf))...)
	_, err := jailGet(iovecs, 0)
	if err != nil {
		return nil, err
	}
	return &jail{
		jailID:   jailID,
		jailName: string(namebuf),
	}, nil
}

func jailParseParam(parameters map[string]interface{}) ([]syscall.Iovec, error) {
	iovecs := make([]syscall.Iovec, 0)
	for key, value := range parameters {
		parIovec, err := paramToIOVec(key, value)
		if err != nil {
			return nil, err
		}
		iovecs = append(iovecs, parIovec ...)
	}
	return iovecs, nil
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

func jailCreate(parameters map[string]interface{}) (*jail, error) {
	name, err := jailParametersGetName(parameters)
	if err != nil {
		return nil, err
	}

	iovecs, err := jailParseParam(parameters)
	if err != nil {
		return nil, err
	}

	jailID, err := jailSet(iovecs, jailFlagCreate)
	if err != nil {
		return nil, err
	}
	return &jail{
		jailID:   jailID,
		jailName: name,
	}, nil
}

//JailCreate creates a Jail with the given parameters, no validation is done atm
//accepted types for interface{}: int32/*int32/uint32/*uint32/string/bool/[]byte
//byte slices MUST be null terminated if the OS expects a string var.
func JailCreate(jailParameters map[string]interface{}) (Jail, error) {
	return jailCreate(jailParameters)
}

func (j *jail) Name() string {
	return j.jailName
}

func (j *jail) ID() int {
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
