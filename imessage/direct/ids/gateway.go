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

package ids

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"howett.net/plist"

	"github.com/beeper/imessage/imessage/direct/util/httputil"
)

type bundleNames struct {
	BundleName string        `plist:"BundleName" json:"bundle_name,omitempty"`
	MVNOs      []bundleNames `plist:"MVNOs" json:"mvnos,omitempty"`
}

func (b bundleNames) BundleNames() (names []string) {
	if b.BundleName != "" {
		names = append(names, b.BundleName)
	}
	for _, mvno := range b.MVNOs {
		names = append(names, mvno.BundleNames()...)
	}
	return
}

type gatewayInfo struct {
	MobileDeviceCarriersByMCCMNC               map[string]bundleNames `plist:"MobileDeviceCarriersByMccMnc"`
	MobileDeviceCarrierBundlesByProductVersion map[string]any         `plist:"MobileDeviceCarrierBundlesByProductVersion"`
}

var cachedGatewayInfo *gatewayInfo

func getGatewayInfo(ctx context.Context) (*gatewayInfo, error) {
	if cachedGatewayInfo != nil {
		return cachedGatewayInfo, nil
	}

	req, err := httputil.Prepare(ctx, http.MethodGet, gatewayFetchURL, nil)
	if err != nil {
		return nil, err
	}

	_, data, err := httputil.Do(httputil.Normal, req)
	if err != nil {
		return nil, err
	}

	cachedGatewayInfo = &gatewayInfo{}
	_, err = plist.Unmarshal(data, cachedGatewayInfo)
	if err != nil {
		return nil, err
	}
	return cachedGatewayInfo, nil
}

func GetCarrierInfo(ctx context.Context, url string) (map[string]any, error) {
	req, err := httputil.Prepare(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	_, data, err := httputil.Do(httputil.Normal, req)
	if err != nil {
		return nil, err
	}

	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}

	for _, file := range reader.File {
		if strings.HasPrefix(file.Name, "Payload/") && strings.HasSuffix(file.Name, "/carrier.plist") {
			carrierFile, err := file.Open()
			if err != nil {
				return nil, err
			}
			defer carrierFile.Close()
			carrierFileData, err := io.ReadAll(carrierFile)
			if err != nil {
				return nil, err
			}

			carrierInfo := map[string]any{}
			err = plist.NewDecoder(bytes.NewReader(carrierFileData)).Decode(&carrierInfo)
			if err != nil {
				return nil, err
			}
			return carrierInfo, nil
		}
	}
	return nil, fmt.Errorf("no carrier info found")
}

func GetGatewayByMCCMNC(ctx context.Context, mccmnc string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	gatewayInfo, err := getGatewayInfo(ctx)
	if err != nil {
		return "", err
	}

	bundleNames, ok := gatewayInfo.MobileDeviceCarriersByMCCMNC[mccmnc]
	if !ok {
		return "", fmt.Errorf("no gateways found for MCCMNC %v", mccmnc)
	}

	for _, bundleName := range bundleNames.BundleNames() {
		carrierInfoRaw, ok := gatewayInfo.MobileDeviceCarrierBundlesByProductVersion[bundleName]
		if !ok {
			continue
		}
		carrierInfo, ok := carrierInfoRaw.(map[string]any)
		if !ok {
			continue
		}

		var maxVersion float64
		var bundleURLForMaxVersion string
		for version, bundleInfoRaw := range carrierInfo {
			if v, err := strconv.ParseFloat(version, 64); err == nil && v > maxVersion {
				bundleInfo, ok := bundleInfoRaw.(map[string]any)
				if !ok {
					return "", fmt.Errorf("bundle info not a map")
				}

				maxVersion = v
				bundleURLForMaxVersion, ok = bundleInfo["BundleURL"].(string)
				if !ok {
					return "", fmt.Errorf("bundle url not found")
				}
			}
		}
		if bundleURLForMaxVersion != "" {
			carrierInfo, err := GetCarrierInfo(ctx, bundleURLForMaxVersion)
			if err != nil {
				return "", err
			}
			switch carrierInfo["PhoneNumberRegistrationGatewayAddress"].(type) {
			case string:
				return carrierInfo["PhoneNumberRegistrationGatewayAddress"].(string), nil
			case []any:
				addresses := carrierInfo["PhoneNumberRegistrationGatewayAddress"].([]any)
				gateway, ok := addresses[0].(string)
				if !ok {
					return "", fmt.Errorf("gateway not a string")
				}
				return gateway, nil
			}
		}
	}
	return "", fmt.Errorf("no gateways found for MCCMNC %s", mccmnc)
}
