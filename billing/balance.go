package billing

// Deprecated: Use models.CentsToMicrocents instead.
func CentsToNanos(cents int64) int64 {
	return cents * 1000000
}

// Deprecated: Use models.MicrocentsToCents instead.
func NanosToCents(nanos int64) int64 {
	return nanos / 1000000
}

func DollarsToCents(dollars int64) int64 {
	return dollars * 100
}

func CentsToDollars(cents int64) int64 {
	return cents / 100
}

// Deprecated: Use DollarsToCents then models.CentsToMicrocents instead.
func DollarsToNanos(dollars int64) int64 {
	return dollars * 1000000 * 100
}

// Deprecated: Use models.MicrocentsToCents then CentsToDollars instead.
func NanosToDollars(nanos int64) int64 {
	return nanos / 1000000 / 100
}
