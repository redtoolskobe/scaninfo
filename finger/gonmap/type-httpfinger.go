package gonmap

import (
	"crypto/x509"
	"io"
	"io/ioutil"
	"net/http"

	"github.com/redtoolskobe/scaninfo/model"

	"github.com/redtoolskobe/scaninfo/finger/lib/httpfinger"
	"github.com/redtoolskobe/scaninfo/finger/lib/iconhash"
	"github.com/redtoolskobe/scaninfo/finger/lib/misc"
	"github.com/redtoolskobe/scaninfo/finger/lib/shttp"

	"github.com/PuerkitoBio/goquery"
	"github.com/redtoolskobe/scaninfo/finger/urlparse"
)

type HttpFinger struct {
	URL              *urlparse.URL
	StatusCode       int
	Response         string
	ResponseDigest   string
	Title            string
	Header           string
	HeaderDigest     string
	HashFinger       string
	KeywordFinger    string
	PeerCertificates *x509.Certificate
	Length           int
	Websitle         string
	Favicons         *[]model.Fingers
	Keywords         *[]model.Fingers
}

func NewHttpFinger(url *urlparse.URL, k *[]model.Fingers, f *[]model.Fingers) *HttpFinger {
	return &HttpFinger{
		URL:              url,
		Websitle:         "",
		StatusCode:       0,
		Response:         "",
		ResponseDigest:   "",
		Title:            "",
		Length:           0,
		Header:           "",
		HashFinger:       "",
		KeywordFinger:    "",
		PeerCertificates: nil,
		Keywords:         k,
		Favicons:         f,
	}
}
func (h *HttpFinger) LoadHttpResponse(url *urlparse.URL, resp *http.Response) {
	h.Title = getTitle(shttp.GetBody(resp))
	h.StatusCode = resp.StatusCode
	h.Header = getHeader(resp.Header.Clone())
	h.Length = len(getResponse(shttp.GetBody(resp)))
	h.HeaderDigest = getHeaderDigest(resp.Header.Clone())
	h.Response = getResponse(shttp.GetBody(resp))
	h.HashFinger = GetFingerByHash(*url, *h.Favicons)
	h.KeywordFinger = GetFingerByKeyword(h.Header, h.Title, h.Response, *h.Keywords)
	_ = resp.Body.Close()
}

func getTitle(resp io.Reader) string {
	query, err := goquery.NewDocumentFromReader(resp)
	if err != nil {
		//fmt.Println(err.Error())
		return ""
	}
	result := query.Find("title").Text()
	result = misc.FixLine(result)
	//Body.Close()
	return result
}

func getHeader(header http.Header) string {
	return shttp.Header2String(header)
}

func getResponse(resp io.Reader) string {
	body, err := ioutil.ReadAll(resp)
	if err != nil {
		//fmt.Println(err.Error())
		return ""
	}
	bodyStr := string(body)
	return bodyStr
}

func getHeaderDigest(header http.Header) string {
	if header.Get("SERVER") != "" {
		return "server:" + header.Get("SERVER")
	}
	return ""
}

func GetFingerByKeyword(header string, title string, body string, k []model.Fingers) string {
	run := httpfinger.Keywords{k}
	return run.Match(header, title, body)
}

func GetFingerByHash(url urlparse.URL, f []model.Fingers) string {
	resp, err := shttp.GetFavicon(url)
	if err != nil {
		//fmt.Println(err.Error())
		return ""
	}
	if resp.StatusCode != 200 {
		return ""
	}
	hash, err := iconhash.Get(resp.Body)
	if err != nil {
		return ""
	}
	_ = resp.Body.Close()
	run := httpfinger.Favicons{f}
	return run.Match(hash)
}

func (h *HttpFinger) LoadCert(resp *http.Response) {
	if resp.TLS != nil {
		h.PeerCertificates = resp.TLS.PeerCertificates[0]
	}
}
