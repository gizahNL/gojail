package gojail

import (
	"unsafe"
)

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
