# gameon-go-mapclient
Go client for Gameontext map service

This is a client project for gameontext.org allowing Go applications to query the map service. 

WIP, additional usage (eg, query by name/room registration) to follow.

## Usage

### certPath
When running Gameon locally, the Map service uses a self signed https certificate, and you need to 
tell the client the path to this to enable connections. If talking to the real gameon servers, then 
this can be left as an empty string. 

### url
URL For map service. 

### apiKey
Obtainable after logging into GameOn and visiting the Map options page. (top right, looks like a block of appartments)

### userID
Obtainable after logging into GameOn and visiting the User options page. (top right, looks like a chess pawn)


```
import mapclient "github.com/BarDweller/gameon-go-mapclient"

func main() {
  certpath := "../.gameontext.onlycert.pem"
  url := "https://192.168.99.100/map/v1/sites"
  apiKey := "***Map Key for Gameon Login***"
  userID := "dummy.DevUser"
  
  mapAPI := mapclient.New(url,apiKey,userID,certpath)
  site := mapAPI.getSite("firstroom")
  fmt.Println(site)
}
```
