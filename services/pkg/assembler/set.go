// SPDX-FileCopyrightText: 2025 Eyad Issa <eyadlorenzo@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-only

package assembler

type Set[T comparable] map[T]struct{}

// NewSet creates a new Set from a slice of items.
func NewSet[T comparable](items ...T) Set[T] {
	set := make(Set[T])
	for _, item := range items {
		set[item] = struct{}{}
	}
	return set
}

// Contains checks if the set contains the specified item.
func (s Set[T]) Contains(item T) bool {
	_, exists := s[item]
	return exists
}

// Add adds an item to the set.
func (s Set[T]) Add(item T) {
	s[item] = struct{}{}
}

// AddAll adds multiple items to the set.
func (s Set[T]) AddAll(items ...T) {
	for _, item := range items {
		s[item] = struct{}{}
	}
}

func (s Set[T]) AddSet(other Set[T]) {
	for item := range other {
		s[item] = struct{}{}
	}
}

// Remove removes an item from the set.
func (s Set[T]) Remove(item T) {
	delete(s, item)
}

// Items returns a slice of all items in the set.
func (s Set[T]) Items() []T {
	items := make([]T, 0, len(s))
	for item := range s {
		items = append(items, item)
	}
	return items
}
