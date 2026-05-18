package progress

import "io"

// ProgressReader wraps an io.Reader and reports bytes read via the OnProgress
// callback. Total is the expected total byte count if known (e.g. from a
// Content-Length header); pass 0 when unknown and callbacks will still fire
// with Current set.
type ProgressReader struct {
	Reader     io.Reader
	Total      int64
	Current    int64
	OnProgress func(current, total int64)
}

// Read implements io.Reader.
func (pr *ProgressReader) Read(p []byte) (int, error) {
	n, err := pr.Reader.Read(p)
	pr.Current += int64(n)
	if pr.OnProgress != nil {
		pr.OnProgress(pr.Current, pr.Total)
	}
	return n, err
}
