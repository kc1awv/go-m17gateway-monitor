/*
Copyright (C) 2024 Steve Miller KC1AWV

This program is free software: you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the Free
Software Foundation, either version 3 of the License, or (at your option)
any later version.

This program is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
more details.

You should have received a copy of the GNU General Public License along with
this program. If not, see <http://www.gnu.org/licenses/>.
*/

package main

// base40Chars is the character set used for encoding callsigns
const (
	base40Chars = " ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-/."
)

// decodeCallsign decodes a 6-byte address into a callsign
func decodeCallsign(encoded []byte) string {
	address := uint64(0)

	for _, b := range encoded {
		address = address*256 + uint64(b)
	}

	callsign := ""
	for address > 0 {
		idx := address % 40
		callsign += string(base40Chars[idx])
		address /= 40
	}

	return callsign
}
