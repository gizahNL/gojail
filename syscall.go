package gojail

import (
	"errors"
	"fmt"
	"net"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

//JailID is used to identify jails
type JailID int32

const (
	//JailFlagCreate use with JailSet to create a jail
	JailFlagCreate = 0x01
	//JailFlagUpdate use with JailSet to update an existing jail
	JailFlagUpdate = 0x02
	//JailFlagAttach use with JailSet to also attach the running process to the jail
	JailFlagAttach = 0x04
	//JailFlagDying allow jails marked as dying
	JailFlagDying = 0x08

	maxhostnamelen = 256
	errormsglen    = 1024
)

var (
	iovErrmsg = []byte("errmsg\000")
)

//JailGet gets values for the parameters in the []syscall.Iovec
func JailGet(iovecs []syscall.Iovec, flags int) (JailID, error) {
	return jailIOVSyscall(syscall.SYS_JAIL_GET, iovecs, flags)
}

//JailSet creates or modifies jails with paramets provided in []syscall.Iovec
func JailSet(iovecs []syscall.Iovec, flags int) (JailID, error) {
	return jailIOVSyscall(syscall.SYS_JAIL_SET, iovecs, flags)
}

//JailAttach attaches the current process to the jail
func JailAttach(jid JailID) error {
	return jailJidSyscall(syscall.SYS_JAIL_ATTACH, jid)
}

//JailRemove destroys the jail, killing all processes in it
func JailRemove(jid JailID) error {
	return jailJidSyscall(syscall.SYS_JAIL_ATTACH, jid)
}

//JailGetName gets the name of the jail associated with JailID
func JailGetName(jid JailID) (string, error) {
	namebuf := make([]byte, maxhostnamelen)

	getparams := make(map[string]interface{})
	getparams["jid"] = jid
	getparams["name"] = namebuf

	iovecs, err := JailParseParametersToIovec(getparams)
	if err != nil {
		return "", err
	}

	_, err = JailGet(iovecs, 0)
	if err != nil {
		return "", err
	}

	return string(namebuf), nil
}

//JailGetID gets the JailID of jail with the given name
func JailGetID(name string) (JailID, error) {
	getparams := make(map[string]interface{})

	jid, err := strconv.Atoi(name)
	if err != nil {
		if jid == 0 {
			return JailID(0), nil
		}
		getparams["jid"] = int32(jid)
	} else {
		getparams["name"] = name
	}

	iovecs, err := JailParseParametersToIovec(getparams)
	if err != nil {
		return -1, nil
	}

	return JailGet(iovecs, 0)
}

//JailParseParametersToIovec parses a map[string]interface{} parameter set to []syscall.Iovec
//for use in Jail syscalls requiring []syscall.Iovec
//Byte slices & pointers are considered out variables and will be filled with JailGet.
//for setting handing over variables use strings or ints instead.
//gojail uses errmsg, and will error out if it's passed as a key
//No validation is done w.r.t. the type required by the jail parameter
func JailParseParametersToIovec(parameters map[string]interface{}) ([]syscall.Iovec, error) {
	iovecs := make([]syscall.Iovec, 0)
	for key, value := range parameters {
		if key == "errmsg" {
			return nil, errors.New("Usage of errmsg is reserved by gojail")
		}
		parIovec, err := paramToIOVec(key, value)
		if err != nil {
			return nil, err
		}
		iovecs = append(iovecs, parIovec...)
	}
	return iovecs, nil
}

func jailIOVSyscall(callnum uintptr, iovecs []syscall.Iovec, flags int) (JailID, error) {
	errbuf, erriov := makeErrorIov()

	iovecs = append(iovecs, erriov...)

	jid, _, errno := syscall.Syscall(callnum, uintptr(unsafe.Pointer(&iovecs[0])), uintptr(len(iovecs)), uintptr(flags))
	if int32(jid) == -1 || errno != 0 {
		if errbuf[0] == 0 {
			return JailID(jid), errno
		}
		return JailID(jid), errors.New(string(errbuf))
	}
	return JailID(jid), nil
}

func jailJidSyscall(callnum uintptr, jid JailID) error {
	_, _, errno := syscall.Syscall(callnum, uintptr(jid), 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func paramToIOVec(key string, value interface{}) ([]syscall.Iovec, error) {
	var val *byte

	name, err := syscall.ByteSliceFromString(key)
	if err != nil {
		return nil, err
	}
	valsize := int(4)
	switch v := value.(type) {
	case int32:
		val = (*byte)(unsafe.Pointer(&v))
	case uint32:
		val = (*byte)(unsafe.Pointer(&v))
	case JailID:
		val = (*byte)(unsafe.Pointer(&v))
	case *int32:
		val = (*byte)(unsafe.Pointer(v))
	case *uint32:
		val = (*byte)(unsafe.Pointer(v))
	case *JailID:
		val = (*byte)(unsafe.Pointer(&v))
	case string:
		//Special case: some variables either "disabled", "new" or "inherit"
		//in normal config, but actually map to 0, 1 ,2
		switch v {
		case "disabled":
			tmp := int32(0)
			val = (*byte)(unsafe.Pointer(&tmp))
		case "new":
			tmp := int32(1)
			val = (*byte)(unsafe.Pointer(&tmp))
		case "inherit":
			tmp := int32(2)
			val = (*byte)(unsafe.Pointer(&tmp))
		default:
			val, err = syscall.BytePtrFromString(v)
			if err != nil {
				return nil, err
			}
			valsize = len(v) + 1
		}
	case []byte:
		val = &v[0]
		valsize = len(v)
	case []net.IP:
		state := 0 //0 -> not initialized, 1 -> ipv4, 2 -> ipv6
		tmp := make([]byte, 0)
		for _, ip := range v {
			ipv4 := ip.To4()
			if ipv4 == nil {
				if state == 1 {
					return nil, errors.New("Mixing ipv4 & ipv6 not allowed")
				}
				state = 2
				tmp = append(tmp, []byte(ip)...)
			} else {
				if state == 2 {
					return nil, errors.New("Mixing ipv4 & ipv6 not allowed")
				}
				state = 1
				tmp = append(tmp, ipv4...)
			}
			val = &tmp[0]
			valsize = len(tmp)
		}

	case bool:
		if !v && !strings.HasPrefix(key, "no") {
			tmp, err := syscall.ByteSliceFromString("no" + key)
			if err != nil {
				return nil, err
			}
			name = tmp
		} else if v && strings.HasPrefix(key, "no") {
			tmp, err := syscall.ByteSliceFromString(strings.TrimPrefix(key, "no"))
			if err != nil {
				return nil, err
			}
			name = tmp
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
