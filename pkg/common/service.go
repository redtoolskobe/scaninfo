package common

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

/**
  服务识别相关处理函数
  rcv: 通过对比banner信息，解析服务信息

*/

func ComparePackets(rcv []byte, rcvSize int, szBan *string, szSvcName *string) int {

	var dwRecognition = UNKNOWN_PORT
	var buf = rcv[:]
	//var buf = rcv[:rcvSize]
	//var bufUp = bytes.ToUpper(buf)
	// DNS
	// 将缓存数据转换成可打印字符

	var printBuf string
	var cHex string
	var szFlagDns = []byte{0x76, 0x65, 0x72, 0x73, 0x69, 0x6F, 0x6E, 0x04, 0x62, 0x69, 0x6E, 0x64}
	var MagicCookie = []byte{0x1a, 0x2b, 0x3c, 0x4d}
	var PcAnyWhereMark_Low = []byte{0x00, 0x58, 0x08}  // PcAnyWhere服务标识(低版本)
	var PcAnyWhereMark_High = []byte{0x1b, 0x59, 0x32} // PcAnyWhere服务标识(高版本)
	var szFlag_LDAP = []byte{0x02, 0x01, 0x01, 0x61}
	var szFlag_RADMIN = []byte{0x01, 0x00, 0x00, 0x00}

	for i := 0; i < rcvSize; i++ {
		if !strconv.IsPrint(rune(buf[i])) {
			cHex = fmt.Sprintf("\\x%02x", buf[i]) // 不可打印字符
		} else {
			cHex = fmt.Sprintf("%c", buf[i]) // 可打印字符
		}

		printBuf += cHex
	}

	var bufUp = bytes.ToUpper([]byte(printBuf))

	var cFlag_MongoDB = []byte{0x4d, 0x09, 0x50, 0x00}
	var cBit_MongoDB []byte

	if rcvSize < 4 {
		goto Return
	}
	if bytes.Equal(buf[:3], []byte("220")) {
		*szBan = printBuf
		if bytes.Contains(bufUp, []byte("FTP")) || bytes.Contains(bufUp, []byte("FILEZILLA")) || bytes.Contains(bufUp, []byte("SERVICE READY FOR NEW USER")) {
			*szSvcName = "ftp"
			dwRecognition = FTP
		} else if bytes.Contains(bufUp, []byte("SMTP")) {
			// 这里比较的是原始字符串还是大写的字符串？
			*szSvcName = "smtp"
			dwRecognition = SMTP
		} else if bytes.Contains(buf, []byte("VMware Authentication Daemon Version")) {
			*szSvcName = "vmware-auth"
			dwRecognition = VM_AUTH_DAEMON
		} else {
			*szSvcName = "ftp|smtp"
			dwRecognition = FTP_OR_SMTP
		}
		goto Return
	}

	if bytes.Equal(buf[:4], []byte("421 ")) || bytes.Equal(buf[:4], []byte("550 ")) {
		*szBan = printBuf

		if bytes.Contains(bufUp, []byte("NO CONNECTIONS ALLOWED FROM YOUR IP")) || bytes.Contains(bufUp, []byte("UNABLE TO OPEN CONFIGURATION FILE")) {
			*szSvcName = "ftp"
			dwRecognition = FTP_NOT_ALLOWED_OR_NOT_AVAILABLE
		} else if bytes.Contains(bufUp, []byte("SMTP")) || bytes.Contains(bufUp, []byte(" SPAM")) || bytes.Equal(bufUp[:len("421 4.3.2 SERVICE NOT AVAILABLE")], []byte("421 4.3.2 SERVICE NOT AVAILABLE")) {
			*szSvcName = "smtp"
			dwRecognition = SMTP_NOT_ALLOWED_OR_NOT_AVAILABLE
		} else {
			*szSvcName = "ftp|smtp"
			dwRecognition = FTP_OR_SMTP_SERVICE_NOT_AVAILABLE
		}
		goto Return
	}

	if bytes.Equal(buf[:3], []byte("554")) {
		// 554 表示SMTP服务器拒绝当前主机访问
		*szBan = printBuf
		*szSvcName = "smtp"

		dwRecognition = SMTP_NOT_ALLOWED_OR_NOT_AVAILABLE

		goto Return
	}

	if bytes.Equal(buf[:9], []byte("rblsmtpd:")) {
		// 反垃圾邮件
		*szBan = printBuf
		*szSvcName = "smtp"
		dwRecognition = SMTP

		goto Return
	}

	// POP
	if bytes.Equal(buf[:4], []byte("+OK ")) {
		*szBan = printBuf
		*szSvcName = "pop"
		dwRecognition = POP3

		goto Return
	}

	if bytes.Equal(buf[:12], []byte("200 poppassd")) {
		*szBan = printBuf
		*szSvcName = "pop"
		dwRecognition = POPPASSD

		goto Return
	}

	// IMAP4
	if bytes.Equal(buf[:5], []byte("* OK ")) {
		*szBan = printBuf
		*szSvcName = "imap"

		dwRecognition = IMAP4

		goto Return
	}

	// VNC
	if bytes.Equal(buf[:4], []byte("\x52\x46\x42\x20")) {
		*szSvcName = "vnc"
		if len(buf) > 10 {
			*szBan = fmt.Sprintf("RFB %c.%c", buf[6], buf[10])

		} else {
			*szBan = fmt.Sprintf("RFB *.*")
		}

		dwRecognition = VNC
		goto Return
	}

	// SSH
	if bytes.Equal(bufUp[:4], []byte("SSH-")) {
		*szBan = printBuf
		*szSvcName = "ssh"
		dwRecognition = SSH

		goto Return
	}

	// MYSQL  TODO::  默认使用了小端序，需要考虑大端序的情况
	if rcvSize > 7 && buf[4] == 0xff && buf[0] == uint8(rcvSize-4) {
		*szSvcName = "mysql"
		//var uErr uint16

		uErr := binary.LittleEndian.Uint16([]byte(buf[5:7]))

		if uErr == 1129 {
			*szBan = "BLOCKED"
			dwRecognition = MySQL_BLOCKED
		} else {
			*szBan = "NOT ALLOWED"
			dwRecognition = MySQL_NOT_ALLOWED
		}

		goto Return

	}

	if rcvSize > 5 && buf[4] >= 10 {
		// TODO::
		index := strings.Index(printBuf, "\\x00\\x00\\x00\\x0a")

		if index != -1 {
			right := printBuf[len("\\x00\\x00\\x00\\x0a")+index:]
			iFind := strings.Index(right, "\\x00")
			if iFind != -1 {
				left := right[:iFind]
				*szBan = left
				*szSvcName = "mysql"
				dwRecognition = MySQL

				goto Return
			}
		}
	}

	// ROS TODO::
	if strings.Contains(printBuf, "\\x13\\x02list") {
		*szSvcName = "MikroTik"
		dwRecognition = ROUTEROS

		goto Return
	}

	// Java-RMI  TODO::
	if strings.Contains(printBuf, "|com.code42.messaging.security.") {
		*szSvcName = "JavaRMI"
		*szBan = "CrashPlan online backup"

		dwRecognition = JAVARMI_CRASHPLAN

		goto Return
	}

	if strings.Index(printBuf, "\\xac\\xed\\x00\\x05") == 0 {
		*szSvcName = "JavaRMI"
		*szBan = printBuf

		dwRecognition = JAVARMI

		goto Return
	}

	// JDWP
	if bytes.Equal(buf[:len("JDWP-Handshake")], []byte("JDWP-Handshake")) {
		*szSvcName = "jdwp"
		dwRecognition = JDWP

		goto Return
	}

	// jabber
	if bytes.Contains(buf, []byte("jabber.org")) &&
		(bytes.EqualFold(buf[:len("<stream:error xmlns:")], []byte("<stream:error xmlns:")) &&
			bytes.EqualFold(buf[:len("<?xml version=")], []byte("<?xml version=")) &&
			bytes.EqualFold(buf[:len("<stream:stream")], []byte("<stream:stream"))) {
		*szSvcName = "jabber"
		dwRecognition = JABBER

		goto Return
	}

	// dtspcd
	if bytes.Equal(buf[:8], []byte("00000000")) {
		*szSvcName = "dtspcd"
		dwRecognition = DTSPCD

		// TODO::
		//*szBan = printBuf
		n := bytes.IndexAny(buf, "/.")

		if n != -1 {
			// Unknown:Unknown:主机名:OS:版本:Arch
			// SPC_5MGMaa:2000:sapsol:AIX:1:00F995DD4C00
			tmpbuf := buf[n:]
			x := n + 2 // 无用字符长度
			banTmp := tmpbuf[2 : rcvSize-x+2]

			for i := 0; i < rcvSize-x-1; i++ {
				if banTmp[i] == 0x00 {
					banTmp[i] = 0x3a
				}
			}

			*szBan = string(banTmp)
		}

		goto Return
	}

	// IBM-DB2
	if bytes.Contains(buf, []byte("DB2DAS")) && bytes.Contains(buf, []byte("SQL")) {
		*szSvcName = "ibm-db2"
		dwRecognition = IBMDB2
		// TODO::
		//*szBan = printBuf
		n := bytes.IndexAny(buf, "SQL")

		if n != -1 {
			buftmp := buf[n:]

			szMajorVersion := buftmp[3:5]
			szMinorVersion := buftmp[5:7]
			szBuildNumber := buftmp[7:9]

			*szBan = fmt.Sprintf("%d.%s.%d", szMajorVersion, szMinorVersion, szBuildNumber)
		}

		goto Return
	}

	// DNS
	//var szFlagDns = [12]byte{0x76, 0x65, 0x72, 0x73, 0x69, 0x6F, 0x6E, 0x04, 0x62, 0x69, 0x6E, 0x64}

	if buf[1] == uint8(rcvSize-2) && bytes.Contains(buf, szFlagDns) {
		// TODO::
		*szSvcName = "dns"
		dwRecognition = DNS_NOBANNER

		// 0xc0 0x0c 0x00 0x10 [2位Class] [4位Time to Live] [2位 Data] [1位 TXT] [Txt]
		szAnswersFlag := []byte{0xc0, 0x0c, 0x00, 0x10}

		n := bytes.Index(buf, szAnswersFlag)
		if n != -1 {
			buftmp := buf[n:]
			if buftmp[12] > 0 {
				dwRecognition = DNS
				*szBan = string(buftmp[13 : 13+buftmp[12]])
			}
		} else {
			szSOAFlag := []byte{0xc0, 0x0c, 0x00, 0x06}
			n := bytes.Index(buf, szSOAFlag)
			if n != -1 {
				buftmp := buf[n:]
				dwRecognition = DNS
				*szBan = string(buftmp[15 : buf[11]-4*5-2-1-2])
			}
		}

		if len(*szBan) == 0 {
			*szBan = "-NOBANNER-"
		}

		goto Return
	}

	if buf[1] == byte(rcvSize-2) && buf[3] == 0x06 {
		dwRecognition = DNS_NOBANNER
		*szSvcName = "dns"
		*szBan = "-NOBANNER-"

		goto Return
	}

	// WEBLOGIC-t3
	if rcvSize > 5 && bytes.Equal(buf[:5], []byte("HELO:")) {
		*szSvcName = "WebLogic-t3"
		dwRecognition = WEBLOGIC

		// TODO::
		//*szBan = printBuf
		n := strings.Index(printBuf, "\\x0a")
		if n != -1 {
			bantmp := printBuf[:n]

			*szBan = strings.ReplaceAll(bantmp, "HELO:", "")
		} else {
			*szBan = printBuf
		}
		goto Return
	}

	if bytes.Contains(buf, []byte("filter blocked Socket, weblogic.security.net.FilterException")) {
		*szSvcName = "WebLogic-t3"
		dwRecognition = WEBLOGIC

		*szBan = "Weblogic Filter Blocked t3/t3s"

		goto Return
	}

	// HTTP | RTSP  TODO:: szBan
	if bytes.Index(bufUp, []byte("HTTP/")) == 0 || bytes.Index(bufUp, []byte("RTSP/1")) == 0 {
		if bytes.Index(bufUp, []byte("HTTP/")) == 0 {
			dwRecognition = HTTP
			*szSvcName = "http"
		} else {
			dwRecognition = RTSP
			*szSvcName = "rtsp"
		}

		//*szBan = printBuf
		n := strings.Index(printBuf, "\\x0d\\x0aServer:")
		if n != -1 {
			bantmp := printBuf[len("\\x0d\\x0aServer:")+n:]
			idx := strings.Index(bantmp, "\\x0d\\x0a")
			if idx != -1 {
				*szBan = string(bantmp[:idx])
				goto Return
			}

		}
		// HTTP 打印100个字符就够了，不然整个网页太长
		if len(printBuf) > 100 {
			*szBan = printBuf[:100]
		} else {
			*szBan = printBuf
		}
		goto Return
	}

	// bandwidth-test TODO::
	if strings.EqualFold(printBuf, "\\x01\\x00\\x00\\x00") {
		dwRecognition = UNKNOWN_SVC
		*szSvcName = "bandwidth-test"
		*szBan = "MikroTik bandwidth-test server"

		goto Return
	}

	// // h.239 TODO::
	if strings.EqualFold(printBuf, "BadRecord") {
		dwRecognition = UNKNOWN_SVC
		*szSvcName = "h.239"
		*szBan = "Polycom People+Content IP H.239"

		goto Return
	}

	// h323q931 TODO::
	if strings.EqualFold(printBuf, "\\x03\\x00\\x000\\x08\\x02\\x00\\x00}\\x08\\x02\\x80\\xe2\\x14\\x01\\x00~\\x00\\x1d\\x05\\x08 \\x19\\x00\\x06\\x00\\x08\\x91J\\x00\\x05\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00") {
		dwRecognition = UNKNOWN_SVC
		*szSvcName = "h323q931"
		*szBan = "Polycom ViewStation H.323"

		goto Return
	}

	// RDP
	if buf[0] == 0x03 && buf[1] == 0x00 && buf[2] == 0x00 {
		dwRecognition = RDP
		*szSvcName = "rdp"

		if bytes.Equal(buf[:len(os______old)], os______old) {
			*szBan = "Windows Server 2003 or before"
		} else if bytes.Equal(buf[:len(os___xrdp_1)], os___xrdp_1) ||
			bytes.Equal(buf[:len(os___xrdp_2)], os___xrdp_2) ||
			bytes.Equal(buf[:len(os___xrdp_3)], os___xrdp_3) ||
			bytes.Equal(buf[:len(os___xrdp_4)], os___xrdp_4) {
			// xrdp
			*szBan = "xrdp"
		} else if bytes.Equal(buf[:len(os___2008_1)], os___2008_1) ||
			bytes.Equal(buf[:len(os___2008_2)], os___2008_2) ||
			bytes.Equal(buf[:len(os___2008_3)], os___2008_3) {
			*szBan = "Windows Server 2008 [R2] [Standard/Enterprise/Datacenter]"
		} else if bytes.Equal(buf[:len(os___2012_1)], os___2012_1) ||
			bytes.Equal(buf[:len(os___2012_2)], os___2012_2) ||
			bytes.Equal(buf[:len(os__2012_r2)], os__2012_r2) {
			*szBan = "Windows Server 2012 [R2]"
		} else if bytes.Equal(buf[:len(os__Vista_1)], os__Vista_1) {
			*szBan = "Windows Vista or later"
		} else if bytes.Equal(buf[:len(os_Multiple_1)], os_Multiple_1) ||
			bytes.Equal(buf[:len(os_Multiple_2)], os_Multiple_2) {
			*szBan = "Windows [7/8/10/Server] 2003/2008/2012 [R2] [Standard/Enterprise] [x64] Edition"
		} else {
			*szBan = printBuf
		}

		goto Return
	}

	// ssl / tls
	if (buf[0] == 0x15 || buf[0] == 0x16) && buf[1] == 0x03 {
		// TODO::
		cBit_SSL, err := IntToBytes(rcvSize-5, 2)
		if err != nil {
			//fmt.Println(err)
			dwRecognition = UNKNOWN_PORT
			goto Return
		}

		if buf[3] == 0x00 || (buf[3] == cBit_SSL[1] && buf[4] == cBit_SSL[0]) {
			// 这里仅做服务识别
			dwRecognition = SSL_TLS
			*szSvcName = "ssl/tls"
			*szBan = "--"
			goto Return
		}
	}

	// MSSQL

	if buf[3] == byte(rcvSize) && buf[0] == 0x04 {
		*szSvcName = "mssql"
		dwRecognition = MSSQL

		// http://blogs.sqlsentry.com/team-posts/latest-builds-sql-server-2016/
		var szSQLVer string
		dwMajorVersion := buf[29]
		dwMinorVersion := buf[30]
		dwBuildNumber := uint16(buf[31])*256 + uint16(buf[32])

		if dwMajorVersion < 5 || dwMajorVersion > 14 {
			dwRecognition = UNKNOWN_SVC // 版本不存在
		}

		switch dwMajorVersion {
		case 6:
			if dwMinorVersion == 50 {
				szSQLVer += " 6.5"
			}
		case 7:
			szSQLVer += " 7"
		case 8, 80:
			szSQLVer += " 2000"
		case 9:
			szSQLVer += " 2005"
		case 10:
			szSQLVer += " 2008"
		case 11:
			szSQLVer += " 2012"
		case 12:
			szSQLVer += " 2014"
		case 13:
			szSQLVer += " 2016"
		}

		if dwMajorVersion < 6 {
			szSQLVer += " [earlier than 6.5]"
		}

		if dwMajorVersion == 10 {
			if dwMinorVersion == 50 {
				szSQLVer += " R2"
			}
		}

		if dwMajorVersion > 12 {
			szSQLVer += " [Later than 2014]"
		}

		switch dwMinorVersion {
		case 50:
			if dwBuildNumber == 2500 {
				szSQLVer += " SP1"
			} else if dwBuildNumber == 4000 {
				szSQLVer += " SP2"
			}
		case 194:
			szSQLVer += " RTM"
		//case 384:
		//	szSQLVer += " SP1"
		//case 534:
		//	szSQLVer += " SP2"
		//case 760:
		//	szSQLVer += " SP3"
		case 0:
			if dwMajorVersion == 8 && dwBuildNumber == 2039 {
				szSQLVer += " SP4"
			} else if dwMajorVersion == 9 && dwBuildNumber == 1399 {
				szSQLVer += " RTM"
			} else if dwMajorVersion == 9 && dwBuildNumber == 2047 {
				szSQLVer += " SP1"
			} else if dwMajorVersion == 9 && (dwBuildNumber == 3042 || dwBuildNumber == 3073) {
				szSQLVer += " SP2"
			} else if dwMajorVersion == 9 && dwBuildNumber == 4035 {
				szSQLVer += " SP3"
			} else if dwMajorVersion == 10 && dwBuildNumber == 1600 {
				szSQLVer += " RTM"
			} else if dwMajorVersion == 10 && dwBuildNumber == 2531 {
				szSQLVer += " SP1"
			} else if dwMajorVersion == 10 && dwBuildNumber == 4000 {
				szSQLVer += " SP2"
			}
		}

		szSQLNum := fmt.Sprintf("%d.%d.%d", dwMajorVersion, dwMinorVersion, dwBuildNumber)
		*szBan = fmt.Sprintf("MSSQL Server%s %s", szSQLVer, szSQLNum)

		if dwRecognition != UNKNOWN_SVC {
			goto Return
		}
	}

	// Oracle 判断是否允许TNSLSNR
	if bytes.Contains(buf, []byte("Y(DESCRIPTION=(TMP=)(VSNNUM=")) || bytes.Contains(buf, []byte(")(ERROR_STACK=(ERROR=(CODE=")) {
		// TODO
		if n := strings.Index(printBuf, "(VSNNUM="); n != -1 {
			buftmp := printBuf[n+8:]
			if idx := strings.Index(buftmp, ")(ERR="); idx != -1 {
				tmp := buftmp[:idx]
				if i, err := strconv.Atoi(tmp); err == nil {
					i = i << 4
					ver, err := IntToBytes(i, 4)
					if err == nil {
						h := ver[3] >> 4
						l := ver[3] << 4
						l = l >> 4
						p := ver[1] >> 4
						q := ver[0] >> 4

						*szBan = fmt.Sprintf("%d.%d.%d.%d.%d", h, l, ver[2], p, q)
						*szSvcName = "oracle"
						dwRecognition = ORACLE

						goto Return
					}
				}

			}
		}
	}

	if n := strings.Index(printBuf, "TNSLSNR"); n != -1 {
		// 允许TNSLSNR查询
		// TODO::
		buftmp := printBuf[len(printBuf)-n:]
		*szBan = strings.ReplaceAll(buftmp, "\\x0a\\x09", " / ")
		*szSvcName = "oracle"
		dwRecognition = ORACLE

		goto Return
	}

	// Redis
	if bytes.Equal(buf[:len("+PONG")], []byte("+PONG")) {
		// 可以获取到版本信息
		dwRecognition = REDIS
		*szSvcName = "redis"
		// TODO::
		//*szBan = printBuf
		if n := strings.Index(printBuf, "redis_version:"); n != -1 {
			buftmp := printBuf[len(printBuf)-n-14:]
			if idx := strings.Index(buftmp, "\\x0d\\x0a"); idx != -1 {
				bleft := buftmp[:idx]
				*szBan = bleft
			} else {
				*szBan = printBuf
			}

		} else {
			*szBan = printBuf
		}

		goto Return
	}

	if bytes.Contains(buf, []byte("-NOAUTH Authentication required")) ||
		bytes.Contains(buf, []byte("-ERR operation not permitted")) ||
		bytes.Contains(buf, []byte("-ERR wrong number of arguments for '")) ||
		bytes.Contains(buf, []byte("-ERR unknown command '")) ||
		bytes.Contains(buf, []byte("-ERR unknown command `")) {
		dwRecognition = REDIS_AUTH
		*szSvcName = "redis"
		*szBan = "NOAUTH, Authentication required"

		goto Return
	}

	if bytes.Contains(buf, []byte("-DENIED Redis is running in protected mode because protected mode is enabled")) {
		*szSvcName = "redis"
		*szBan = "DENIED, Redis is running in protected mode"
		dwRecognition = REDIS_DENIED

		goto Return
	}

	// vpn-pptp
	if uint8(rcvSize) == buf[1] && bytes.Equal(buf[4:8], MagicCookie) {
		*szSvcName = "vpn-pptp"
		dwRecognition = VPN_PPTP

		szHostName := buf[28:92]
		szVendorName := buf[92:156]

		*szBan = fmt.Sprintf("%s|%s", szHostName, szVendorName)

		goto Return
	}

	// RSYNC
	if bytes.EqualFold(buf[:9], []byte("@RSYNCD: ")) {
		//csbuf := fmt.Sprintf("%s", buf)
		//csbuf = strings.ReplaceAll(csbuf, "\r", "\\x0d")
		//csbuf = strings.ReplaceAll(csbuf, "\n", "\\x0a")

		*szBan = printBuf
		dwRecognition = RSYNC
		*szSvcName = "rsync"

		goto Return
	}

	// PCANYWHERE
	if bytes.Equal(buf[:3], PcAnyWhereMark_Low) {
		*szSvcName = "pcanywhere"
		dwRecognition = PCANYWHERE

		goto Return
	}

	if bytes.Equal(buf[:3], PcAnyWhereMark_High) {
		*szSvcName = "pcanywhere"
		dwRecognition = PCANYWHERE
		*szBan = "高版本"

		goto Return
	}

	// memcached
	if bytes.Equal(buf[:len("STAT pid ")], []byte("STAT pid ")) {
		*szSvcName = "memcached"
		dwRecognition = MEMCACHED
		// TODO: 获取版本号
		if n := strings.Index(printBuf, "STAT version "); n != -1 {
			buftmp := printBuf[len(printBuf)-n-13:]
			if idx := strings.Index(buftmp, "\\x0d\\x0a"); n != -1 {
				*szBan = buftmp[:idx]
				goto Return
			}
		}
		*szBan = "Memcached"

		goto Return
	}

	if bytes.Index(buf, []byte("SERVER_ERROR unauthorized, null bucket")) == 0 {
		*szSvcName = "memcached"
		dwRecognition = MEMCACHED
		*szBan = "SERVER_ERROR unauthorized"

		goto Return
	}

	// Mongodb  TODO::
	//fmt.Println(cBit_MongoDB)
	cBit_MongoDB, _ = IntToBytes(rcvSize, 4)
	if bytes.Equal(buf[:4], cBit_MongoDB) && bytes.Equal(buf[8:12], cFlag_MongoDB) {
		if bytes.Contains(buf, []byte("host")) && bytes.Contains(buf, []byte("version")) &&
			bytes.Contains(buf, []byte("uptime")) && bytes.Contains(buf, []byte("ok")) {
			*szSvcName = "mongodb"
			dwRecognition = MONGODB

			var szVer, szHost string

			if k := bytes.Index(buf, []byte("version")); k != -1 {
				szVer = fmt.Sprintf("%s", buf[k+len("version")+1+4:k+len("version")+1+4+6])
			}

			if n := bytes.Index(buf, []byte("host")); n != -1 {
				szHost = fmt.Sprintf("%s", buf[n+len("host")+1+4:n+len("host")+1+4+6])
			}

			*szBan = fmt.Sprintf("%s|%s", szVer, szHost)
		} else if bytes.Contains(buf, []byte("errmsg")) {
			dwRecognition = MONGODB_AUTH
			*szSvcName = "mongodb"
			*szBan = "unauthorized"
		}

		if dwRecognition != UNKNOWN_SVC {
			goto Return
		}
	}

	// LDAP
	if bytes.Contains(buf, szFlag_LDAP) {
		*szSvcName = "ldap"
		dwRecognition = LDAP

		goto Return
	}

	// SIP
	if bytes.EqualFold(buf[:4], []byte("SIP/")) {
		*szSvcName = "sip"
		dwRecognition = SIP

		// TODO 获取szBan
		mark := "\\x0d\\x0aServer:"
		n := strings.Index(printBuf, "\\x0d\\x0aServer:")
		if n == -1 {
			mark = "\\x0d\\x0aUser-Agent:"
			n = strings.Index(printBuf, "\\x0d\\x0aUser-Agent:")
		}

		if n != -1 {
			buftmp := printBuf[len(printBuf)-n-len(mark):]
			if idx := strings.Index(buftmp, "\\x0d\\x0a"); idx != -1 {
				*szBan = buftmp[:idx]
				goto Return
			}
		}

		*szBan = printBuf

		goto Return
	}

	// RAdmin
	if bytes.Equal(buf[:4], szFlag_RADMIN) && (buf[4] == 0x25 || buf[4] == 0x09) {
		*szSvcName = "radmin"
		dwRecognition = RADMIN
		*szBan = printBuf

		goto Return
	}

	// POSTGRESQL
	if buf[0] == 0x45 && buf[4] == byte(rcvSize-1) &&
		(bytes.Contains(buf, []byte("FATAL")) || bytes.Contains(buf, []byte("Fpostmaster.c"))) {
		*szSvcName = "postgresql"
		dwRecognition = POSTGRESQL

		goto Return
	}

	if buf[0] == 0x52 && (buf[4] == byte(rcvSize-1) || bytes.Contains(buf, []byte("server_version\x00")) ||
		bytes.EqualFold(buf[:len("R\\x00\\x00\\x00\\x08\\x00\\x00\\x00\\x00")], []byte("R\\x00\\x00\\x00\\x08\\x00\\x00\\x00\\x00"))) {
		*szSvcName = "postgresql"
		dwRecognition = POSTGRESQL

		goto Return
	}

	// NETBIOS(445)
	if buf[0] == 0 && buf[3] == byte(rcvSize-4) && buf[5] == 0x53 && buf[6] == 0x4d && buf[7] == 0x42 {
		*szSvcName = "microsoft-ds"
		dwRecognition = MICROSOFT_DS

		//iLen := 4 + 32 + 45
		//szDomainName := buf[iLen:rcvSize]
		//szHostName := buf[iLen+(len(szDomainName)+1)*2:rcvSize]

		// TODO::
		*szBan = printBuf

		goto Return
	}

	// msrcp(135)
	if buf[0] == 0x05 && buf[8] == byte(rcvSize) {
		*szSvcName = "msrcp"
		dwRecognition = DECRPC

		if !bytes.EqualFold(buf, []byte("\\x05\\x00\\x0d\\x03\\x10\\x00\\x00\\x00\\x18\\x00\\x00\\x00\\x00\\x08\\x01@\\x04\\x00\\x01\\x05\\x00\\x00\\x00\\x00")) {
			*szBan = printBuf
		}

		goto Return
	}

	// netbios-ssn 139
	if buf[0] == 0x83 && buf[1] == 0x00 && buf[4] == 0x8f {
		*szSvcName = "netbios-ssn"
		dwRecognition = NETBIOS_SSN

		goto Return
	}

	// MMS (Microsoft Media Server Protocol)
	if rcvSize > 15 && buf[12] == 0x4d && buf[13] == 0x4d && buf[14] == 0x53 && buf[15] == 0x20 {
		*szSvcName = "mms"
		dwRecognition = MMS

		goto Return
	}

	// SVRLOC
	if bytes.Contains(buf, []byte("service:service-agent://")) ||
		(buf[0] == 0x02 && buf[1] == 0x0b && buf[13] == 0x02 && buf[14] == 0x65 && buf[15] == 0x6e) {
		*szSvcName = "svrloc"
		dwRecognition = SVRLOC

		goto Return
	}

	// AJP13
	if strings.EqualFold(printBuf, "AB\\x00\\x01\\x09") {
		*szSvcName = "ajp13"
		dwRecognition = AJP13
		*szBan = "Apache Jserv (Protocol v1.3)"

		goto Return
	}

	//fmt.Println(rcvSize)
	if strings.EqualFold(printBuf, "AB\\x00") {
		*szSvcName = "ajp13"
		dwRecognition = AJP13
		*szBan = "Apache Jserv"

		goto Return
	}

	// nfs TODO::
	if strings.Index(printBuf, "\\x80\\x00\\x00") == 0 &&
		strings.Contains(printBuf, "\\x10l\\x8e") {
		*szSvcName = "nfs"
		dwRecognition = NFS

		goto Return
	}

	// lotusnotes (1352) TODO::
	if strings.Index(printBuf, "\\x84\\x00\\x00\\x00") == 0 {
		*szSvcName = "lotusnotes"
		dwRecognition = LOTUSNOTES

		goto Return
	}

	// TELNET
	if bytes.Contains(buf, []byte("ogin:")) || bytes.Contains(buf, []byte("ccount:")) ||
		bytes.Contains(buf, []byte("ser:")) || bytes.Contains(buf, []byte("ame:")) ||
		bytes.Contains(buf, []byte("assword:")) || bytes.Contains(buf, []byte("telnet")) ||
		bytes.Contains(buf, []byte("System administrator")) || bytes.Contains(buf, []byte("%connection closed by remote host!")) ||
		bytes.Contains(buf, []byte("not allowed now, you may try")) || bytes.Contains(buf, []byte("All user interfaces are used, please try later")) ||
		(buf[0] == 0xff && buf[1] == 0xfd) || (buf[0] == 0xff && buf[1] == 0xfb) {
		dwRecognition = TELNET
		*szSvcName = "telnet"
		*szBan = printBuf

		goto Return
	}

	// subversion
	if rcvSize > 5 && bytes.Equal(buf[:len("( success ( ")], []byte("( success ( ")) {
		dwRecognition = SVNSERVE
		*szSvcName = "svn"

		goto Return
	}

	// elasticsearch
	if strings.EqualFold(printBuf, "This is not a HTTP port") {
		*szSvcName = "elasticsearch"
		dwRecognition = ELASTICSEARCH
		*szBan = "Elasticsearch binary API"

		goto Return
	}

	// bgp
	if strings.Index(printBuf, "\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff") == 0 {
		*szSvcName = "bgp"
		dwRecognition = UNKNOWN_SVC

		goto Return
	}

	// ldp
	if strings.Index(printBuf, "\\x00\\x01\\x00\\x1c\\x00\\x00\\x00\\x00\\x00\\x00") == 0 {
		*szSvcName = "ldp"
		dwRecognition = UNKNOWN_SVC

		goto Return
	}

	// xmpp
	if strings.EqualFold(printBuf, "</stream:stream>") {
		*szSvcName = "xmpp"
		dwRecognition = UNKNOWN_SVC
		*szBan = printBuf

		goto Return
	}

	// Hikvision IPCam control port
	if strings.Index(printBuf, "\\x00\\x00\\x00\\x10\\x00\\x00\\x00") == 0 {
		dwRecognition = UNKNOWN_SVC
		*szSvcName = "ipcam"
		*szBan = printBuf

		goto Return
	}

	// shoutcast
	if strings.EqualFold(printBuf, "invalid password\\x0d\\x0a") {
		dwRecognition = UNKNOWN_SVC
		*szSvcName = "shoutcast"
		*szBan = "SHOUTcast server"

		goto Return
	}

	// zebra
	if strings.EqualFold(printBuf, "Vty password is not set.\\x0d\\x0a") {
		dwRecognition = UNKNOWN_SVC
		*szSvcName = "zebra"
		*szBan = "Quagga routing software"

		goto Return
	}

	// 判断是HTTP或者HTTPS,
	// if bytes.Contains(bufUp, []byte("You're speaking plain HTTP to an SSL-enabled server port")) {
	// 	dwRecognition = SSL_TLS
	// 	*szSvcName = "ssl"

	// 	// HTTP/HTTPS 打印100个字符就够了，不然整个网页太长
	// 	*szBan = printBuf[:100]
	// 	goto Return
	// }

	// 未知服务，返回数据修改成16进制保存（数据包大于0）
	if rcvSize > 0 {
		dwRecognition = UNKNOWN_SVC
		*szSvcName = "unknown"
		*szBan = printBuf
		//*szBan = string(buf)
	}

Return:
	return dwRecognition
}

// 整形向字符切片转换
func IntToBytes(n int, b byte) ([]byte, error) {
	switch b {
	case 1:
		tmp := int8(n)
		bytesBuffer := bytes.NewBuffer([]byte{})
		err := binary.Write(bytesBuffer, binary.BigEndian, &tmp)
		return bytesBuffer.Bytes(), err
	case 2:
		tmp := int16(n)
		bytesBuffer := bytes.NewBuffer([]byte{})
		//err := binary.Write(bytesBuffer, binary.BigEndian, &tmp)
		err := binary.Write(bytesBuffer, binary.LittleEndian, &tmp)
		return bytesBuffer.Bytes(), err
	case 3, 4:
		tmp := int32(n)
		bytesBuffer := bytes.NewBuffer([]byte{})
		//err := binary.Write(bytesBuffer, binary.BigEndian, &tmp)
		err := binary.Write(bytesBuffer, binary.LittleEndian, &tmp)
		return bytesBuffer.Bytes(), err
	}
	return nil, fmt.Errorf("IntToBytes b param is invaild")
}

//func bytesToUint16(buf []byte) uint16 {
//	return binary.LittleEndian.Uint16(buf)
//}
