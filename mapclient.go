package mapclient

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"
)

// MapService api to access GameOn Map service
type MapService struct {
	url       string
	apiKey    string
	systemID  string
	trustCert []byte
}

//ConnectionDetails represents how to talk to a GameOn room.
type ConnectionDetails struct {
	ConnectionType string `json:"type,omitempty"`
	Target         string `json:"target,omitempty"`
	Token          string `json:"token,omitempty"`
	HealthURL      string `json:"healthUrl,omitempty"`
}

//Exit describes an exit from a Room
type Exit struct {
	ID                string            `json:"_id"`
	Name              string            `json:"name,omitempty"`
	FullName          string            `json:"fullName,omitempty"`
	Door              string            `json:"door,omitempty"`
	ConnectionDetails ConnectionDetails `json:"connectionDetails,omitempty"`
}

//Coord is the location in the map (handy for visualisation)
type Coord struct {
	X int `json:"x"`
	Y int `json:"y"`
}

//RoomInfo represents info about a Room
type RoomInfo struct {
	Name              string            `json:"name,omitempty"`
	FullName          string            `json:"fullName,omitempty"`
	Description       string            `json:"description,omitempty"`
	RepositoryURL     string            `json:"repositoryUrl,omitempty"`
	Doors             map[string]string `json:"doors,omitempty"`
	ConnectionDetails ConnectionDetails `json:"connectionDetails,omitempty"`
}

//Site represents info about a record the Map Service is maintaining.
type Site struct {
	ID              string          `json:"_id"`
	Info            RoomInfo        `json:"info"`
	Owner           string          `json:"owner,omitempty"`
	CreatedOn       string          `json:"createdOn,omitempty"`
	AssignedOn      string          `json:"assignedOn,omitempty"`
	CreatedInstant  string          `json:"createdInstant,omitempty"`
	AssignedInstant string          `json:"assignedInstant,omitempty"`
	Type            string          `json:"type"`
	Coord           Coord           `json:"coord,omitempty"`
	Exits           map[string]Exit `json:"exits,omitempty"`
}

//New creates an instance of the Map Service API
//(use empty apiKey/systemID for unauthenticated)
func New(url, apiKey, systemID, certPath string) *MapService {
	var cert []byte
	if certPath != "" {
		severCert, err := ioutil.ReadFile(certPath)
		if err != nil {
			log.Fatal("Could not load server certificate!")
		}
		cert = severCert
	} else {
		cert = nil
	}
	return &MapService{url, apiKey, systemID, cert}
}

//GetSites returns all sites the Map Service knows about
func (m *MapService) GetSites() ([]Site, error) {
	var site []Site
	if response, status, err := m.doGet(m.url); err == nil {
		if status != 200 {
			err = fmt.Errorf("Bad Status %d : %s", status, response)
		} else {
			err = json.Unmarshal(response, &site)
		}
		if err == nil {
			return site, nil
		} else {
			return nil, err
		}
	} else {
		return nil, err
	}
}

//GetSite returns a particular site, or error if unknown
func (m *MapService) GetSite(id string) (Site, error) {
	var site Site
	if response, status, err := m.doGet(strings.Join([]string{m.url, id}, "/")); err == nil {
		fmt.Println(string(response))
		if status != 200 {
			err = fmt.Errorf("Bad Status %d : %s", status, response)
		} else {
			err = json.Unmarshal(response, &site)
		}
		if err == nil {
			return site, nil
		} else {
			return Site{}, err
		}
	} else {
		return Site{}, err
	}
}

func (m *MapService) doGet(url string) ([]byte, int, error) {
	return m.doInvoke("GET", url, nil)
}

func (m *MapService) doDelete(url string) ([]byte, int, error) {
	return m.doInvoke("DELETE", url, nil)
}

func (m *MapService) doPost(url string, body []byte) ([]byte, int, error) {
	return m.doInvoke("POST", url, body)
}

func (m *MapService) getClient() *http.Client {
	var tr *http.Transport
	if m.trustCert != nil {
		CAPool := x509.NewCertPool()
		CAPool.AppendCertsFromPEM(m.trustCert)
		config := &tls.Config{RootCAs: CAPool}
		tr = &http.Transport{TLSClientConfig: config}
	}
	var client *http.Client
	switch {
	case tr != nil:
		client = &http.Client{
			Timeout:   time.Second * 15,
			Transport: tr}
	default:
		client = &http.Client{
			Timeout: time.Second * 15,
		}
	}
	return client
}

func (m *MapService) hash(message []byte) string {
	h := sha256.New()
	h.Write(message)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func (m *MapService) buildHmac(tokens ...string) string {
	key := []byte(m.apiKey)
	h := hmac.New(sha256.New, key)
	s := ""
	for _, t := range tokens {
		s += t
	}
	h.Write([]byte(s))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func (m *MapService) addAuthenticationHeaders(req *http.Request, body []byte) {
	// Build the authentication values that Game On! requires. If
	// the body is empty, do not include it in the calculations.
	var bodyHash, sig, ts string
	oldStyle := true
	if oldStyle {
		ts = time.Now().UTC().Format(time.RFC3339)
		if len(body) > 0 {
			bodyHash = m.hash(body)
			req.Header.Set("gameon-sig-body", bodyHash)
			sig = m.buildHmac(m.systemID, ts, bodyHash)
		} else {
			sig = m.buildHmac(m.systemID, ts)
		}
	} else {
		ts = time.Now().UTC().Format(time.RFC1123)
		if len(body) > 0 {
			bodyHash = m.hash(body)
			req.Header.Set("gameon-sig-body", bodyHash)
			fmt.Println("Method", req.Method, "uri ", req.RequestURI)
			sig = m.buildHmac(req.Method, req.RequestURI, m.systemID, ts, bodyHash)
		} else {
			fmt.Printf("Method '%s' '%s'\n", req.Method, req.URL.Path)
			sig = m.buildHmac(req.Method, req.URL.Path, m.systemID, ts)
		}
	}
	// Set the required headers.
	req.Header.Set("gameon-id", m.systemID)
	req.Header.Set("gameon-date", ts)
	req.Header.Set("gameon-signature", sig)
}

func (m *MapService) doInvoke(method, url string, body []byte) ([]byte, int, error) {
	var client = m.getClient()
	req, _ := http.NewRequest(method, url, bytes.NewBuffer(body))
	if m.apiKey != "" {
		m.addAuthenticationHeaders(req, body)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json,text/plain")
	if response, err := client.Do(req); err == nil {
		if buf, err := ioutil.ReadAll(response.Body); err == nil {
			return buf, response.StatusCode, nil
		} else {
			return nil, response.StatusCode, err
		}
	} else {
		return nil, -1, err
	}
}
