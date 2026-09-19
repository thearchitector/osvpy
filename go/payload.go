package main

import "strings"

// Projection DTOs remain convenient at ingestion. Retained nodes contain only
// string IDs, optional scalar tags, enums, and spans into chunked word storage.
type span struct{ Start, Count uint32 }

const nilSpanStart = ^uint32(0)

type listEntry struct {
	span
	next uint32
}
type payloadBuilder struct {
	strings map[string]uint32
	lists   map[uint64]uint32
	entries slabs[listEntry]
	scratch []uint32
}

func (b *batchBuilder) stringID(s string) uint32 {
	if id, ok := b.payload.strings[s]; ok {
		return id
	}
	if b.payload.strings == nil {
		b.payload.strings = make(map[string]uint32)
	}
	// Own the bytes instead of retaining a substring of an upstream buffer.
	s = strings.Clone(s)
	id := checked(b.report.Strings.Append(s) + 1)
	b.payload.strings[s] = id
	return id
}
func (r *reportStore) stringAt(id uint32) string {
	if id == 0 {
		panic("missing string")
	}
	return *r.Strings.At(int(id) - 1)
}
func (b *batchBuilder) optionalString(s *string) uint32 {
	if s == nil {
		return 0
	}
	return b.stringID(*s)
}
func optionalBool(b *bool) uint8 {
	if b == nil {
		return 0
	}
	if *b {
		return 2
	}
	return 1
}

var statusNames = [...]string{"not_evaluated", "compliant", "unknown", "noncompliant", "no_reported_fix", "reported"}

func statusID(s string) uint8 {
	for i, name := range statusNames {
		if s == name {
			return uint8(i)
		}
	}
	panic("invalid status")
}
func (b *batchBuilder) packWords(words []uint32) span {
	if words == nil {
		return span{Start: nilSpanStart}
	}
	if len(words) == 0 {
		return span{}
	}
	h := uint64(14695981039346656037)
	for _, word := range words {
		h = (h ^ uint64(word)) * 1099511628211
	}
	return b.internWords(words, h)
}

// Fingerprints only select a collision chain; full equality always decides.
func (b *batchBuilder) internWords(words []uint32, hash uint64) span {
	p := &b.payload
	if p.lists == nil {
		p.lists = make(map[uint64]uint32)
	}
	for id := p.lists[hash]; id != 0; {
		e := p.entries.At(int(id) - 1)
		equal := int(e.Count) == len(words)
		if equal {
			for i, word := range words {
				if *b.report.Words.At(int(e.Start) + i) != word {
					equal = false
					break
				}
			}
		}
		if equal {
			return e.span
		}
		id = e.next
	}
	s := span{checked(b.report.Words.Len()), checked(len(words))}
	checked(b.report.Words.Len() + len(words))
	for _, word := range words {
		b.report.Words.Append(word)
	}
	id := p.entries.Append(listEntry{s, p.lists[hash]})
	p.lists[hash] = checked(id + 1)
	return s
}
func (b *batchBuilder) packStrings(values []string) span {
	if values == nil {
		return span{Start: nilSpanStart}
	}
	if len(values) == 0 {
		return span{}
	}
	words := b.payload.scratch[:0]
	for _, value := range values {
		words = append(words, b.stringID(value))
	}
	s := b.packWords(words)
	b.payload.scratch = words
	return s
}
func (b *batchBuilder) packSeverities(values []reportSeverity) span {
	if values == nil {
		return span{Start: nilSpanStart}
	}
	if len(values) == 0 {
		return span{}
	}
	words := b.payload.scratch[:0]
	for _, v := range values {
		words = append(words, b.stringID(v.Type), b.stringID(v.Source), b.stringID(v.Vector))
	}
	s := b.packWords(words)
	b.payload.scratch = words
	return s
}
func (b *batchBuilder) packReferences(values []reportReference) span {
	if values == nil {
		return span{Start: nilSpanStart}
	}
	if len(values) == 0 {
		return span{}
	}
	words := b.payload.scratch[:0]
	for _, v := range values {
		words = append(words, b.stringID(v.Type), b.stringID(v.URL))
	}
	s := b.packWords(words)
	b.payload.scratch = words
	return s
}

type storedPackage struct {
	Name          uint32
	Version       uint32
	Ecosystem     uint32
	Commit        uint32
	OSPackageName uint32
	PURL          uint32
}

func (b *batchBuilder) packPackage(v reportPackage) storedPackage {
	return storedPackage{Name: b.stringID(v.Name), Version: b.stringID(v.Version), Ecosystem: b.stringID(v.Ecosystem), Commit: b.stringID(v.Commit), OSPackageName: b.stringID(v.OSPackageName), PURL: b.stringID(v.PURL)}
}

type storedAdvisory struct {
	ID               uint32
	Aliases          span
	Summary          uint32
	Modified         uint32
	Published        uint32
	Withdrawn        uint32
	Severities       span
	References       span
	DatabaseSeverity uint32
}

func (b *batchBuilder) packAdvisory(v reportAdvisory) storedAdvisory {
	return storedAdvisory{ID: b.stringID(v.ID), Aliases: b.packStrings(v.Aliases), Summary: b.stringID(v.Summary), Modified: b.optionalString(v.Modified), Published: b.optionalString(v.Published), Withdrawn: b.optionalString(v.Withdrawn), Severities: b.packSeverities(v.Severities), References: b.packReferences(v.References), DatabaseSeverity: b.optionalString(v.DatabaseSeverity)}
}

type storedVulnerability struct {
	ID      uint32
	Aliases span
}

func (b *batchBuilder) packVulnerability(v reportVulnerability) storedVulnerability {
	return storedVulnerability{ID: b.stringID(v.ID), Aliases: b.packStrings(v.Aliases)}
}

type storedContext struct {
	Path             uint32
	SourceType       uint32
	Layer            uint32
	DependencyGroups span
}

func (b *batchBuilder) packContext(v reportContext) storedContext {
	return storedContext{Path: b.stringID(v.Path), SourceType: b.stringID(v.SourceType), Layer: b.optionalString(v.Layer), DependencyGroups: b.packStrings(v.DependencyGroups)}
}

type storedAssessment struct {
	Called      uint8
	Unimportant uint8
	MaxSeverity uint32
}

func (b *batchBuilder) packAssessment(v reportAssessment) storedAssessment {
	return storedAssessment{Called: optionalBool(v.Called), Unimportant: optionalBool(v.Unimportant), MaxSeverity: b.stringID(v.MaxSeverity)}
}

type storedLicense struct {
	Licenses   span
	Policy     span
	Violations span
	Status     uint8
}

func (b *batchBuilder) packLicense(v reportLicense) storedLicense {
	return storedLicense{Licenses: b.packStrings(v.Licenses), Policy: b.packStrings(v.Policy), Violations: b.packStrings(v.Violations), Status: statusID(v.Status)}
}

type storedFix struct {
	Versions   span
	Status     uint8
	Severities span
	Urgencies  span
}

func (b *batchBuilder) packFix(v reportFix) storedFix {
	return storedFix{Versions: b.packStrings(v.Versions), Status: statusID(v.Status), Severities: b.packSeverities(v.Severities), Urgencies: b.packStrings(v.Urgencies)}
}
