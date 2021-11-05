package finger

import (
	"strings"

	"github.com/redtoolskobe/scaninfo/model"

	"github.com/redtoolskobe/scaninfo/finger/gonmap"
	"github.com/redtoolskobe/scaninfo/finger/lib/shttp"
	"github.com/redtoolskobe/scaninfo/finger/urlparse"
)

func getHttpFinger(url *urlparse.URL, loop bool, k *[]model.Fingers, f *[]model.Fingers) *gonmap.HttpFinger {
	r := gonmap.NewHttpFinger(url, k, f)
	if url != nil {
		resp, err := shttp.Get(url.UnParse())
		if err != nil {
			if loop == true {
				return r
			}
			if strings.Contains(err.Error(), "server gave HTTP response") {
				//HTTP协议重新获取指纹
				url.Scheme = "http"
				return getHttpFinger(url, true, k, f)
			}
			if strings.Contains(err.Error(), "malformed HTTP response") {
				//HTTP协议重新获取指纹
				url.Scheme = "https"
				return getHttpFinger(url, true, k, f)
			}
			return r
		}
		if url.Scheme == "https" {
			r.LoadCert(resp)
		}
		r.LoadHttpResponse(url, resp)
		return r
	}
	return r
}

func Run(urlx string, k *[]model.Fingers, f *[]model.Fingers) *gonmap.HttpFinger {
	url, _ := urlparse.Load(urlx)
	return getHttpFinger(url, true, k, f)
}
