package pkg

import "github.com/404tk/lazyscan/pkg/plugins"

var PluginList = map[string]interface{}{
	"docker-remote": plugins.DockerRemote,
	"redis":         plugins.RedisScan,
	"mysql":         plugins.MysqlScan,
	"ssh":           plugins.SshScan,
	"etcd":          plugins.EtcdScan,
	"mssql":         plugins.MssqlScan,
	"postgresql":    plugins.PostgreScan,
	"kube-api":      plugins.KubeAPIServerScan,
	"kubelet":       plugins.KubeletScan,
	"web":           plugins.WebVulnScan,
	"smb":           plugins.SMBScan,
	"wmi":           plugins.WMIScan,
}
