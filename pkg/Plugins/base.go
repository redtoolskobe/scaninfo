package Plugins

var PluginList = map[string]interface{}{
	"ftp":        FtpScan,
	"ssh":        SshScan,
	"findnet":    Findnet,
	"netbios":    NetBIOS,
	"smb":        SmbScan,
	"mssql":      MssqlScan,
	"mysql":      MysqlScan,
	"postgresql": PostgresScan,
	"redis":      RedisScan,
	"memcached":  MemcachedScan,
	"mongodb":    MongodbScan,
	"1000001":    MS17010,
	"1000002":    SmbGhost,
	"1000003":    WebTitle,
}
