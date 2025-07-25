// SPDX-FileCopyrightText: 2025 Eyad Issa <eyadlorenzo@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-only

package analysis

import (
	"encoding/base64"
	"regexp"
	"testing"
	"tulip/pkg/db"

	"github.com/stretchr/testify/assert"
)

func mustDecodeBase64(t *testing.T, s string) string {
	t.Helper()
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("failed to decode base64: %v", err)
	}
	return string(decoded)
}

func TestApplyFlagRegexTags(t *testing.T) {

	makeFlowEntry := func(data ...string) *db.FlowEntry {
		flowItems := make([]db.FlowItem, len(data))
		nextFrom := db.FlowItemFromClient
		for i, d := range data {
			flowItems[i] = db.FlowItem{Raw: []byte(d), From: nextFrom}
			if nextFrom == db.FlowItemFromServer {
				nextFrom = db.FlowItemFromClient
			} else {
				nextFrom = db.FlowItemFromServer
			}
		}

		return &db.FlowEntry{Flow: flowItems, Tags: []string{}, Flags: []string{}}
	}

	cases := []struct {
		name          string
		input         *db.FlowEntry
		regex         string
		expectedTags  []string
		expectedFlags []string
	}{
		{
			"no match",
			makeFlowEntry("banana", "cherry"),
			"[a-z]{10}=",
			[]string{},
			[]string{},
		},
		{
			"single match flag-in",
			makeFlowEntry("FLAG{test}", "OK"),
			"FLAG\\{.*?\\}",
			[]string{"flag-in"},
			[]string{"FLAG{test}"},
		},
		{
			"single match flag-out",
			makeFlowEntry("asking for the flag", "FLAG{test}"),
			"FLAG\\{.*?\\}",
			[]string{"flag-out"},
			[]string{"FLAG{test}"},
		},
		{
			"empty input",
			makeFlowEntry(),
			"a.*",
			[]string{},
			[]string{},
		},
		{
			"real world scenario",
			makeFlowEntry(
				"FLAG{1234}",
				mustDecodeBase64(t, `SFRUUC8xLjEgMjAwIE9LDQpTZXJ2ZXI6IG5naW54LzEuMjcuNQ0KRGF0ZTogRnJpLCAyMCBKdW4gMjAyNSAxNTo1NjowNyBHTVQNCkNvbnRlbnQtVHlwZTogYXBwbGljYXRpb24vanNvbg0KQ29ubmVjdGlvbjogY2xvc2UNCg0KeyJpbnZpdGVzIjogW3siaWQiOiAiMDE5NzhlMDUtY2JkYi03ZDBjLWEwMzMtMzk5OTFhZDVjNGE2IiwgImZyb20iOiAiU2laUkJaVHd6MDcwIiwgInRpdGxlIjogImt2aHQzSHJIRm8iLCAiZGVzY3JpcHRpb24iOiAiNU8wODAxVkJJQUNMU1JQWjZONktVTVA5VlJIMDdBRT0iLCAiZGF0ZSI6ICIyMDMzLTA3LTE1In1dLCAic3VjY2VzcyI6IHRydWV9Cg==`)),
			"[A-Z0-9]{31}=",
			[]string{"flag-out"},
			[]string{"5O0801VBIACLSRPZ6N6KUMP9VRH07AE="},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			reg := regexp.MustCompile(c.regex)
			a := FlagAnalyzer(reg)
			a.Run(c.input)

			assert.Equal(t, c.expectedTags, c.input.Tags, "tags should match expected")
			assert.Equal(t, c.expectedFlags, c.input.Flags, "flags should match expected")
		})
	}
}
