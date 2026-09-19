package main

// Decode complete records only in tests; production reads individual compact fields.
func (r *reportStore) optionalString(id uint32) *string {
	if id == 0 {
		return nil
	}
	s := r.stringAt(id)
	return &s
}

func boolPointer(b uint8) *bool {
	if b == 0 {
		return nil
	}
	v := b == 2
	return &v
}

func (r *reportStore) unpackStrings(s span) []string {
	if s.Start == nilSpanStart {
		return nil
	}
	values := make([]string, s.Count)
	for i := range values {
		values[i] = r.stringAt(*r.Words.At(int(s.Start) + i))
	}
	return values
}

func (r *reportStore) unpackSeverities(s span) []reportSeverity {
	if s.Start == nilSpanStart {
		return nil
	}
	values := make([]reportSeverity, s.Count/3)
	for i := range values {
		start := int(s.Start) + 3*i
		values[i] = reportSeverity{r.stringAt(*r.Words.At(start)), r.stringAt(*r.Words.At(start + 1)), r.stringAt(*r.Words.At(start + 2))}
	}
	return values
}

func (r *reportStore) unpackReferences(s span) []reportReference {
	if s.Start == nilSpanStart {
		return nil
	}
	values := make([]reportReference, s.Count/2)
	for i := range values {
		start := int(s.Start) + 2*i
		values[i] = reportReference{r.stringAt(*r.Words.At(start)), r.stringAt(*r.Words.At(start + 1))}
	}
	return values
}

func (r *reportStore) packageAt(id int) reportPackage {
	v := r.Packages.At(id)
	return reportPackage{Name: r.stringAt(v.Name), Version: r.stringAt(v.Version), Ecosystem: r.stringAt(v.Ecosystem), Commit: r.stringAt(v.Commit), OSPackageName: r.stringAt(v.OSPackageName), PURL: r.stringAt(v.PURL)}
}

func (r *reportStore) advisoryAt(id int) reportAdvisory {
	v := r.AdvisorySources.At(id)
	return reportAdvisory{ID: r.stringAt(v.ID), Aliases: r.unpackStrings(v.Aliases), Summary: r.stringAt(v.Summary), Modified: r.optionalString(v.Modified), Published: r.optionalString(v.Published), Withdrawn: r.optionalString(v.Withdrawn), Severities: r.unpackSeverities(v.Severities), References: r.unpackReferences(v.References), DatabaseSeverity: r.optionalString(v.DatabaseSeverity)}
}

func (r *reportStore) vulnerabilityAt(id int) reportVulnerability {
	v := r.Vulnerabilities.At(id)
	return reportVulnerability{ID: r.stringAt(v.ID), Aliases: r.unpackStrings(v.Aliases)}
}

func (r *reportStore) contextAt(id int) reportContext {
	v := r.Contexts.At(id)
	return reportContext{Path: r.stringAt(v.Path), SourceType: r.stringAt(v.SourceType), Layer: r.optionalString(v.Layer), DependencyGroups: r.unpackStrings(v.DependencyGroups)}
}

func (r *reportStore) assessmentAt(id int) reportAssessment {
	v := r.Assessments.At(id)
	return reportAssessment{Called: boolPointer(v.Called), Unimportant: boolPointer(v.Unimportant), MaxSeverity: r.stringAt(v.MaxSeverity)}
}

func (r *reportStore) licenseAt(id int) reportLicense {
	v := r.Licenses.At(id)
	return reportLicense{Licenses: r.unpackStrings(v.Licenses), Policy: r.unpackStrings(v.Policy), Violations: r.unpackStrings(v.Violations), Status: statusNames[v.Status]}
}

func (r *reportStore) fixAt(id int) reportFix {
	v := r.Fixes.At(id)
	return reportFix{Versions: r.unpackStrings(v.Versions), Status: statusNames[v.Status], Severities: r.unpackSeverities(v.Severities), Urgencies: r.unpackStrings(v.Urgencies)}
}
