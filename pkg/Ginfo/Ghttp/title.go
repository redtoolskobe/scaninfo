package Ghttp

import (
	"net/http"
	"regexp"
	"strings"

	"golang.org/x/net/html"
)

// ExtractTitle from a response
func ExtractTitle(body string, r *http.Response) (title string) {
	var re = regexp.MustCompile(`(?im)<\s*title.*>(.*?)<\s*/\s*title>`)
	for _, match := range re.FindAllString(body, -1) {
		title = html.UnescapeString(trimTitleTags(match))
		break
	}
	// Non UTF-8
	if contentTypes, ok := r.Header["Content-Type"]; ok {
		contentType := strings.ToLower(strings.Join(contentTypes, ";"))
		// special cases
		if strings.Contains(contentType, "charset=gb2312") || strings.Contains(contentType, "charset=gbk") {
			titleUtf8, err := Decodegbk([]byte(title))
			if err != nil {
				return
			}

			return string(titleUtf8)
		}
	}

	return
}

func trimTitleTags(title string) string {
	// trim <title>*</title>
	titleBegin := strings.Index(title, ">")
	titleEnd := strings.Index(title, "</")
	return title[titleBegin+1 : titleEnd]
}

func ExtractFinger(body string, r *http.Response) string {
	var fingers []string

	if r.Header.Get("Set-Cookie") != "" && strings.Contains(r.Header.Get("Set-Cookie"), "rememberMe=deleteMe") {
		fingers = append(fingers, "Shiro!!")
	}
	if body != "" {
		if strings.Contains(body, "servletContextInitParams") {
			fingers = append(fingers, "Spring env!!")
		} else if strings.Contains(body, "logback") {
			fingers = append(fingers, "Spring env!!")
		} else if strings.Contains(body, "Error 404--Not Found") || strings.Contains(body, "Error 403--") {
			fingers = append(fingers, "Weblogic!!")
		} else if strings.Contains(body, "/por/login_psw.csp") {
			fingers = append(fingers, "Sangfor SSL VPN!!")
		} else if strings.Contains(body, "weaver,e-mobile") {
			fingers = append(fingers, "e-mobile!!")
		} else if strings.Contains(body, "ecology") {
			fingers = append(fingers, "ecology!!")
		} else if strings.Contains(body, "e-Bridge") || strings.Contains(body, "wx.weaver") {
			fingers = append(fingers, "e-Bridge!!")
		} else if strings.Contains(body, "Swagger UI") {
			fingers = append(fingers, "Swagger UI!!")
		} else if strings.Contains(body, "4008 111 000") {
			fingers = append(fingers, "Ruijie")
		} else if strings.Contains(body, "Script/SmcScript.js?version=") {
			fingers = append(fingers, "Huawei SMC")
		} else if strings.Contains(body, "/wnm/ssl/web/frame/login.html") {
			fingers = append(fingers, "H3C Router")
		} else if strings.Contains(body, "/+CSCOE+/logon.html") {
			fingers = append(fingers, "Cisco SSLVPN!!")
		} else if strings.Contains(body, "Huawei") || strings.Contains(body, "huawei") || strings.Contains(body, "Hicloud") || strings.Contains(body, "hicloud") || strings.Contains(body, "Vmall") || strings.Contains(body, "vmall") {
			fingers = append(fingers, "Huawei!!")
		} else if strings.Contains(body, "../zentao/theme/zui/css/min.css") {
			fingers = append(fingers, "Zentao!!")
		} else if strings.Contains(body, "UI_component/commonDefine/UI_regex_define.js") {
			fingers = append(fingers, "Huawei Firewall")
		} else if strings.Contains(body, "CDGServer3") {
			fingers = append(fingers, "亿赛通电子文档!!")
		} else if strings.Contains(body, "/zcms/") || strings.Contains(body, "App=ZCMS(ZCMS内容管理系统)") {
			fingers = append(fingers, "ZCMS!!")
		} else if strings.Contains(body, "3F367B74-92D9-4C5E-AB93-234F8A91D5E6") {
			fingers = append(fingers, "云匣子!!")
		} else if strings.Contains(body, "\x2Findex.zul") {
			fingers = append(fingers, "Old 云匣子!!")
		} else if strings.Contains(body, "gHasSecureMail") {
			fingers = append(fingers, "亿邮!!")
		} else if strings.Contains(body, "any_rsa_pas") || strings.Contains(body, "https://sec.anymacro.com") {
			fingers = append(fingers, "Anymail!!")
		} else if strings.Contains(body, "action=\"/coremail/index.jsp?cus=1\"") || strings.Contains(body, "/coremail/common/") {
			fingers = append(fingers, "Coremail!!")
		} else if strings.Contains(body, "\"/r/cms/") {
			fingers = append(fingers, "JEECMS!!")
		} else if strings.Contains(body, "CN/volumn/") {
			fingers = append(fingers, "网刊系统!!")
		} else if strings.Contains(body, "journalx") {
			fingers = append(fingers, "玛格泰克JournalX!!")
		} else if strings.Contains(body, "href=\"/seeyon/skin/dist") || strings.Contains(body, "/seeyon/main.do") {
			fingers = append(fingers, "致远OA!!")
		} else if strings.Contains(body, "StylePath:\"/resource/style") {
			fingers = append(fingers, "蓝凌ekp!!")
		} else if strings.Contains(body, "Office Anywhere") || strings.Contains(body, "general/login_code.php") {
			fingers = append(fingers, "通达OA!!")
		} else if strings.Contains(body, "webmail/se/account/download.do") || strings.Contains(body, "url=/webmail/\"") {
			fingers = append(fingers, "Easysite!!")
		} else if strings.Contains(body, "Zabbix SIA") {
			fingers = append(fingers, "Zabbix!!")
		} else if strings.Contains(body, "Powered by Discuz!") || strings.Contains(body, "content=\"Discuz!") {
			fingers = append(fingers, "Discuz!!")
		}
	}

	return strings.Join(fingers, "|")
}
