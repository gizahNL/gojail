// +build cgo

package gojail

/*
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/param.h>
#include <sys/jail.h>

#define JAIL_ERRMSGLEN  1024

int create_jail_in_child(int parent, int pipefd, char* errbuf, struct iovec *iov, u_int niov)
{
	pid_t pid = fork();
	int res;
	if (pid == 0) {
		res = jail_attach(parent);
		if (res != 0) {
			_exit(EXIT_FAILURE);
		}
		res = jail_set(iov, niov, JAIL_CREATE);
		if (res == -1) {
			write(pipefd, errbuf, JAIL_ERRMSGLEN);
			_exit(EXIT_FAILURE);
		}
		write(pipefd, &res, sizeof(res));
		_exit(EXIT_SUCCESS);
	} else if (pid > 0) {
		pid = waitpid(pid, &res, 0);
		close(pipefd);
		if (WIFEXITED(res)) {
			return WEXITSTATUS(res);
		}
		return 0;
	}
	return EXIT_FAILURE;
}
*/
import "C"

import (
	"os"
	"unsafe"
	"syscall"
)

//go:norace
func testCreateInChild(parentID, iovecs, niovecs uintptr, pipe int) (pid int, err syscall.Errno) {
	var (
		r1 uintptr
		jid int32
		err1 syscall.Errno
	)

	r1, _, err1 = syscall.RawSyscall(syscall.SYS_FORK, 0, 0, 0)
	if err1 != 0 {
		return 0, err1
	}

	if r1 != 0 {
		return int(r1), 0
	}

	r1, _, err1 = syscall.RawSyscall(syscall.SYS_JAIL_ATTACH, uintptr(parentID), 0, 0)
	if err1 != 0 {
		goto childerror
	}

	r1, _, err1 = syscall.RawSyscall(syscall.SYS_JAIL_SET, iovecs, niovecs, JailFlagCreate)
	if err1 != 0 || int(r1) == -1 {
		goto childerror
	}
	jid = int32(r1)
	syscall.RawSyscall(syscall.SYS_WRITE, uintptr(pipe), uintptr(unsafe.Pointer(&jid)), unsafe.Sizeof(jid))
	for {
		syscall.RawSyscall(syscall.SYS_EXIT, 0, 0, 0)
	}


childerror:
	syscall.RawSyscall(syscall.SYS_WRITE, uintptr(pipe), uintptr(unsafe.Pointer(&err1)), unsafe.Sizeof(err1))
	for {
		syscall.RawSyscall(syscall.SYS_EXIT, 253, 0, 0)
	}
}

func (j *jail) CreateChildJail(parameters map[string]interface{}) (Jail, error) {
	name, err := jailParametersGetName(parameters)
	if err != nil {
		return nil, err
	}

	iovecs, err := JailParseParametersToIovec(parameters)
	if err != nil {
		return nil, err
	}

	err = checkAndIncreaseChildMax(j.jailID)
	if err != nil {
		return nil, err
	}

	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, err
	}

	_, erriov := makeErrorIov()

	iovecs = append(iovecs, erriov...)
	syscall.ForkLock.Lock()
	pid, err := testCreateInChild(uintptr(j.jailID), uintptr(unsafe.Pointer(&iovecs[0])), uintptr(len(iovecs)), int(writer.Fd()))
	syscall.ForkLock.Unlock()
	if err != nil {
		return nil, err
	}
	var waitStatus syscall.WaitStatus
	_, err = syscall.Wait4(pid, &waitStatus, 0, nil)
	if err != nil {
		return nil, err
	}
	if waitStatus.ExitStatus() != 0 {
		errnobuf := make([]byte, 4)
		reader.Read(errnobuf)
		errno := (*syscall.Errno)(unsafe.Pointer(&errnobuf[0]))
		return nil, error(errno)

	}
	jidbuf := make([]byte, 4)
	reader.Read(jidbuf)
	jid := (*JailID)(unsafe.Pointer(&jidbuf[0]))
	return &jail{
		jailID:   *jid,
		jailName: name,
	}, nil
}

func checkAndIncreaseChildMax(jid JailID) error {
	var childrenMax, childrenCur int32
	getparam := make(map[string]interface{})
	getparam["jid"] = jid
	getparam["children.max"] = &childrenMax
	getparam["children.cur"] = &childrenCur

	getIovecs, err := JailParseParametersToIovec(getparam)
	if err != nil {
		return err
	}

	_, err = JailGet(getIovecs, 0)
	if err != nil {
		return err
	}

	if childrenCur >= childrenMax {
		setparam := make(map[string]interface{})
		setparam["jid"] = jid
		setparam["children.max"] = childrenMax + 1

		setIovecs, err := JailParseParametersToIovec(setparam)
		if err != nil {
			return err
		}
		_, err = JailSet(setIovecs, JailFlagUpdate)
		return err
	}
	return nil
}
