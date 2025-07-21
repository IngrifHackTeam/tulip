// SPDX-FileCopyrightText: 2025 Eyad Issa <eyadlorenzo@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-only

package assembler

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewSet(t *testing.T) {
	cases := []struct {
		name     string
		input    []string
		expected Set[string]
	}{
		{"empty set", []string{}, Set[string]{}},
		{"single item", []string{"a"}, Set[string]{"a": {}}},
		{"multiple items", []string{"a", "b", "c"}, Set[string]{"a": {}, "b": {}, "c": {}}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			result := NewSet(c.input...)
			assert.Equal(t, len(c.expected), len(result), "set length mismatch")
			for item := range c.expected {
				assert.Contains(t, result, item, "expected item %s to be in the set", item)
			}
		})
	}
}

func TestSetContains(t *testing.T) {
	cases := []struct {
		name     string
		set      Set[string]
		item     string
		expected bool
	}{
		{"item exists", Set[string]{"a": {}}, "a", true},
		{"item does not exist", Set[string]{"a": {}}, "b", false},
		{"empty set", Set[string]{}, "x", false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			result := c.set.Contains(c.item)
			assert.Equal(t, c.expected, result, "expected %v for item %s in set %v", c.expected, c.item, c.set)
		})
	}
}

func TestSetAdd(t *testing.T) {
	cases := []struct {
		name     string
		set      Set[string]
		item     string
		expected Set[string]
	}{
		{"add new item", Set[string]{"a": {}}, "b", Set[string]{"a": {}, "b": {}}},
		{"add existing item", Set[string]{"a": {}}, "a", Set[string]{"a": {}}},
		{"add to empty set", Set[string]{}, "x", Set[string]{"x": {}}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.set.Add(c.item)
			assert.Equal(t, len(c.set), len(c.expected), "set length mismatch")

			for item := range c.expected {
				assert.Contains(t, c.set, item, "expected item %s to be in the set", item)
			}
		})
	}
}

func TestSetAddAll(t *testing.T) {
	cases := []struct {
		name     string
		set      Set[string]
		items    []string
		expected Set[string]
	}{
		{"add multiple new items", Set[string]{"a": {}}, []string{"b", "c"}, Set[string]{"a": {}, "b": {}, "c": {}}},
		{"add some existing items", Set[string]{"a": {}}, []string{"a", "b"}, Set[string]{"a": {}, "b": {}}},
		{"add to empty set", Set[string]{}, []string{"x", "y"}, Set[string]{"x": {}, "y": {}}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.set.AddAll(c.items...)
			assert.Equal(t, len(c.set), len(c.expected), "set length mismatch")
			for item := range c.expected {
				assert.Contains(t, c.set, item, "expected item %s to be in the set", item)
			}
		})
	}
}
