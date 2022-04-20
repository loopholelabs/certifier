/*
	Copyright 2022 Loophole Labs

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

		   http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

// Package utils contains a set of utility functions
package utils

import "strings"

// NormalizeDomain replaces all the periods in a domain (example.com) with hyphens (example-com)
func NormalizeDomain(domain string) string {
	if domain == "" {
		return ""
	}
	return strings.ReplaceAll(domain, ".", "-")
}

// JoinStrings combines multiple strings together using the strings.Builder struct
func JoinStrings(s ...string) string {
	var b strings.Builder
	for _, str := range s {
		b.WriteString(str)
	}
	return b.String()
}
