// beeper-imessage - A Matrix-iMessage puppeting bridge.
// Copyright (C) 2023 Beeper, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package httputil

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
)

func FormatCurl(cli *http.Client, req *http.Request) string {
	var curl []string
	hasBody := false
	if req.GetBody != nil {
		body, _ := req.GetBody()
		if body != http.NoBody {
			b, _ := io.ReadAll(body)
			curl = []string{"echo", base64.StdEncoding.EncodeToString(b), "|", "base64", "-d", "|"}
			hasBody = true
		}
	}
	curl = append(curl, "curl", "-v")
	switch req.Method {
	case http.MethodGet:
		// Don't add -X
	case http.MethodHead:
		curl = append(curl, "-I")
	default:
		curl = append(curl, "-X", req.Method)
	}
	for key, vals := range req.Header {
		kv := fmt.Sprintf("%s: %s", key, vals[0])
		curl = append(curl, "-H", fmt.Sprintf("%q", kv))
	}
	if cli.Jar != nil {
		cookies := cli.Jar.Cookies(req.URL)
		if len(cookies) > 0 {
			cookieStrings := make([]string, len(cookies))
			for i, cookie := range cookies {
				if strings.ContainsAny(cookie.Value, " ,") {
					cookieStrings[i] = fmt.Sprintf(`%s="%s"`, cookie.Name, cookie.Value)
				} else {
					cookieStrings[i] = fmt.Sprintf("%s=%s", cookie.Name, cookie.Value)
				}
			}
			curl = append(curl, "-H", fmt.Sprintf("%q", "Cookie: "+strings.Join(cookieStrings, "; ")))
		}
	}
	if hasBody {
		curl = append(curl, "--data-binary", "@-")
	}
	curl = append(curl, fmt.Sprintf("'%s'", req.URL.String()))
	return strings.Join(curl, " ")
}
