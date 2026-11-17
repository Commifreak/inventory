package agent

import (
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	serviceName    = "InventoryAgent"
	serviceDisplay = "Inventory Agent"
	productName    = "Inventory Agent"
	uninstallKey   = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\InventoryAgent`
)

func envDir(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func installDir() string {
	return filepath.Join(envDir("ProgramFiles", `C:\Program Files`), productName)
}

// DataDir holds config, state and logs (ACL: SYSTEM and Administrators only).
func DataDir() string { return filepath.Join(envDir("ProgramData", `C:\ProgramData`), productName) }

// BinaryPath is the installed agent binary.
func BinaryPath() string { return filepath.Join(installDir(), "inventory-agent.exe") }

var (
	modkernel32 = windows.NewLazySystemDLL("kernel32.dll")
	moduser32   = windows.NewLazySystemDLL("user32.dll")
	modcrypt32  = windows.NewLazySystemDLL("crypt32.dll")
	modnetapi32 = windows.NewLazySystemDLL("netapi32.dll")

	procGetFirmwareEnvironmentVariableExW = modkernel32.NewProc("GetFirmwareEnvironmentVariableExW")
	procGetTickCount64                    = modkernel32.NewProc("GetTickCount64")
	procMessageBoxW                       = moduser32.NewProc("MessageBoxW")
	procCryptProtectData                  = modcrypt32.NewProc("CryptProtectData")
	procCryptUnprotectData                = modcrypt32.NewProc("CryptUnprotectData")
	procNetLocalGroupGetMembers           = modnetapi32.NewProc("NetLocalGroupGetMembers")
	procNetApiBufferFree                  = modnetapi32.NewProc("NetApiBufferFree")
)

// hideWindow prevents console windows for child processes.
func hideWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
}

// ---------------------------------------------------------------------------
// DPAPI (machine scope) - the data directory ACL restricts who can read it.
// ---------------------------------------------------------------------------

type dataBlob struct {
	cbData uint32
	pbData *byte
}

func newBlob(d []byte) *dataBlob {
	if len(d) == 0 {
		return &dataBlob{}
	}
	return &dataBlob{cbData: uint32(len(d)), pbData: &d[0]}
}

func (b *dataBlob) bytes() []byte {
	out := make([]byte, b.cbData)
	copy(out, unsafe.Slice(b.pbData, b.cbData))
	return out
}

const cryptprotectLocalMachine = 0x4
const cryptprotectUIForbidden = 0x1

func protect(s string) (string, error) {
	var out dataBlob
	r, _, err := procCryptProtectData.Call(uintptr(unsafe.Pointer(newBlob([]byte(s)))), 0, 0, 0, 0,
		cryptprotectLocalMachine|cryptprotectUIForbidden, uintptr(unsafe.Pointer(&out)))
	if r == 0 {
		return "", err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.pbData)))
	return "dpapi:" + base64.StdEncoding.EncodeToString(out.bytes()), nil
}

func unprotect(s string) (string, error) {
	if len(s) < 6 || s[:6] != "dpapi:" {
		return s, nil
	}
	raw, err := base64.StdEncoding.DecodeString(s[6:])
	if err != nil {
		return "", err
	}
	var out dataBlob
	r, _, err := procCryptUnprotectData.Call(uintptr(unsafe.Pointer(newBlob(raw))), 0, 0, 0, 0, cryptprotectUIForbidden, uintptr(unsafe.Pointer(&out)))
	if r == 0 {
		return "", err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.pbData)))
	return string(out.bytes()), nil
}

// ---------------------------------------------------------------------------
// UI helpers
// ---------------------------------------------------------------------------

const (
	mbOK          = 0x0
	mbOKCancel    = 0x1
	mbIconError   = 0x10
	mbIconWarning = 0x30
	mbIconInfo    = 0x40
	mbTopmost     = 0x40000
	idOK          = 1
)

func messageBox(title, text string, flags uint32) int {
	t, _ := windows.UTF16PtrFromString(title)
	m, _ := windows.UTF16PtrFromString(text)
	r, _, _ := procMessageBoxW.Call(0, uintptr(unsafe.Pointer(m)), uintptr(unsafe.Pointer(t)), uintptr(flags|mbTopmost))
	return int(r)
}

func isElevated() bool { return windows.GetCurrentProcessToken().IsElevated() }

// relaunchElevated starts the current executable with admin rights (UAC prompt).
func relaunchElevated(args string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exe)
	params, _ := windows.UTF16PtrFromString(args)
	dir, _ := windows.UTF16PtrFromString(filepath.Dir(exe))
	return windows.ShellExecute(0, verb, file, params, dir, windows.SW_SHOWNORMAL)
}

// ---------------------------------------------------------------------------
// misc system information
// ---------------------------------------------------------------------------

func tickCount64() uint64 {
	r, _, _ := procGetTickCount64.Call()
	return uint64(r)
}

// enablePrivilege enables a privilege in the process token (SYSTEM has many
// privileges that are disabled by default).
func enablePrivilege(name string) error {
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &tok); err != nil {
		return err
	}
	defer tok.Close()
	var luid windows.LUID
	n, _ := windows.UTF16PtrFromString(name)
	if err := windows.LookupPrivilegeValue(nil, n, &luid); err != nil {
		return err
	}
	tp := windows.Tokenprivileges{PrivilegeCount: 1}
	tp.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}
	return windows.AdjustTokenPrivileges(tok, false, &tp, 0, nil, nil)
}

// firmwareVar reads a UEFI variable.
func firmwareVar(name, guid string) ([]byte, error) {
	n, _ := windows.UTF16PtrFromString(name)
	g, _ := windows.UTF16PtrFromString(guid)
	size := 64 * 1024
	for i := 0; i < 3; i++ {
		buf := make([]byte, size)
		var attrs uint32
		r, _, err := procGetFirmwareEnvironmentVariableExW.Call(uintptr(unsafe.Pointer(n)), uintptr(unsafe.Pointer(g)),
			uintptr(unsafe.Pointer(&buf[0])), uintptr(size), uintptr(unsafe.Pointer(&attrs)))
		if r != 0 {
			return buf[:r], nil
		}
		if errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
			size *= 4
			continue
		}
		return nil, err
	}
	return nil, windows.ERROR_INSUFFICIENT_BUFFER
}

type localgroupMembersInfo2 struct {
	sid           *windows.SID
	sidUsage      uint32
	domainAndName *uint16
}

// localGroupMembers lists members of a local group ("DOMAIN\name").
func localGroupMembers(group string) ([]string, error) {
	g, _ := windows.UTF16PtrFromString(group)
	var buf *byte
	var read, total uint32
	var resume uintptr
	r, _, _ := procNetLocalGroupGetMembers.Call(0, uintptr(unsafe.Pointer(g)), 2, uintptr(unsafe.Pointer(&buf)),
		0xFFFFFFFF, uintptr(unsafe.Pointer(&read)), uintptr(unsafe.Pointer(&total)), uintptr(unsafe.Pointer(&resume)))
	if r != 0 {
		return nil, syscall.Errno(r)
	}
	defer procNetApiBufferFree.Call(uintptr(unsafe.Pointer(buf)))
	entries := unsafe.Slice((*localgroupMembersInfo2)(unsafe.Pointer(buf)), read)
	var out []string
	for _, e := range entries {
		out = append(out, windows.UTF16PtrToString(e.domainAndName))
	}
	return out, nil
}

// sidName resolves a SID string to "DOMAIN\name".
func sidName(s string) string {
	sid, err := windows.StringToSid(s)
	if err != nil {
		return s
	}
	acc, dom, _, err := sid.LookupAccount("")
	if err != nil {
		return s
	}
	if dom != "" {
		return dom + `\` + acc
	}
	return acc
}

// restrictDir limits a directory to SYSTEM and Administrators.
func restrictDir(path string) error {
	sd, err := windows.SecurityDescriptorFromString("D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}
