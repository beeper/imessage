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

// If we ever need to update these or get additional values, use the following URL:
// https://init.ess.apple.com/WebObjects/VCInit.woa/wa/getBag?ix=3

const (
	idAuthenticateDSIDURL          = "https://profile.ess.apple.com/WebObjects/VCProfileService.woa/wa/authenticateDS"
	idAuthenticatePhoneNumberURL   = "https://identity.ess.apple.com/WebObjects/TDIdentityService.woa/wa/authenticatePhoneNumber"
	idGetDependentRegistrationsURL = "https://identity.ess.apple.com/WebObjects/TDIdentityService.woa/wa/getDependentRegistrations"
	idGetHandlesURL                = "https://profile.ess.apple.com/WebObjects/VCProfileService.woa/wa/idsGetHandles"
	idQueryURL                     = "https://query.ess.apple.com/WebObjects/QueryService.woa/wa/query"
)
