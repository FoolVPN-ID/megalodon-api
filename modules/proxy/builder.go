package proxy

import (
	"fmt"
	"strings"

	"github.com/FoolVPN-ID/megalodon-api/modules/db/users"
	"github.com/FoolVPN-ID/megalodon/common/helper"
	"github.com/FoolVPN-ID/megalodon/common/shared"
	database "github.com/FoolVPN-ID/megalodon/db"
	"github.com/Noooste/azuretls-client"
)

var (
	ModeList      = []string{"cdn", "sni"}
	TransportList = []string{"ws", "grpc", "tcp"}
	PortList      = []int{80, 443}
)

func BuildProxyFieldsFromUser(user *users.UserStruct, baseProxyField database.ProxyFieldStruct) []database.ProxyFieldStruct {
	var (
		results  = []database.ProxyFieldStruct{}
		session  = azuretls.NewSession()
		res, err = session.Get("https://" + baseProxyField.Server + "/api/v1/info")

		serverInfo = map[string]string{
			"country":      "XX",
			"country_name": "oceania",
			"ip":           "192.168.1.1",
			"org":          "Megalodon",
			"region":       "Hindia",
		}
	)

	if err == nil && res.StatusCode == 200 {
		res.MustJSON(&serverInfo)
	}

	for _, mode := range ModeList {
		for _, transport := range TransportList {
			for _, port := range PortList {
				// Filters
				if mode == "cdn" {
					if (transport == "grpc" && port == 80) || (transport == "tcp") {
						continue
					}
				} else {
					if port == 80 {
						continue
					}
				}

				tlsStr := "TLS"
				if port == 80 {
					tlsStr = "NTLS"
				}

				proxyField := baseProxyField

				// vpn config assignment
				proxyField.Ip = serverInfo["ip"]
				proxyField.ServerPort = port
				proxyField.Transport = transport
				proxyField.TLS = port == 443
				proxyField.Path = "/" + user.VPN
				proxyField.ServiceName = user.VPN
				proxyField.ConnMode = mode

				// Geoip assignment
				for _, country := range shared.CountryList {
					if country.Code == serverInfo["country"] {
						proxyField.CountryCode = country.Code
						proxyField.Region = country.Region
						break
					}
				}

				proxyField.Remark = strings.ToUpper(fmt.Sprintf("%d ✨", len(results)+1))
				if user.Relay != "" {
					proxyField.Remark = strings.ToUpper(fmt.Sprintf("%s %s <-", proxyField.Remark, helper.CCToEmoji(user.Relay)))
				}
				proxyField.Remark = strings.ToUpper(fmt.Sprintf("%s %s %s %s %s %s", proxyField.Remark, helper.CCToEmoji(proxyField.CountryCode), serverInfo["org"], transport, mode, tlsStr))

				results = append(results, proxyField)
			}
		}
	}

	return results
}
