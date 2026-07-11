// Package fsops provides structured file operations (read/write/edit/list/stat)
// confined to configured root directories. These give an agent reliable file
// manipulation without shell-quoting pitfalls.
package fsops

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// FS performs file operations confined to Roots.
type FS struct {
	roots        []string
	unrestricted bool
}

// New builds an FS. If roots is empty or contains "/", access is unrestricted.
func New(roots []string) *FS {
	f := &FS{}
	for _, r := range roots {
		clean := filepath.Clean(r)
		if clean == "/" {
			f.unrestricted = true
		}
		f.roots = append(f.roots, clean)
	}
	if len(f.roots) == 0 {
		f.unrestricted = true
	}
	return f
}

// Resolve cleans path (joining relative paths onto base) and confines it to a
// configured root. base may be "" (defaults to the first root or "/").
func (f *FS) Resolve(path, base string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("empty path")
	}
	if base == "" {
		if len(f.roots) > 0 {
			base = f.roots[0]
		} else {
			base = "/"
		}
	}
	var abs string
	if filepath.IsAbs(path) {
		abs = filepath.Clean(path)
	} else {
		abs = filepath.Clean(filepath.Join(base, path))
	}
	if f.unrestricted {
		return abs, nil
	}
	for _, root := range f.roots {
		if abs == root || strings.HasPrefix(abs, root+string(os.PathSeparator)) {
			return abs, nil
		}
	}
	return "", fmt.Errorf("path %q is outside the configured roots", path)
}

// StatInfo is metadata about a path.
type StatInfo struct {
	Path    string `json:"path"`
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	Mode    string `json:"mode"`
	IsDir   bool   `json:"is_dir"`
	ModTime string `json:"mod_time"`
	Exists  bool   `json:"exists"`
}

func (f *FS) Stat(abs string) (StatInfo, error) {
	info, err := os.Stat(abs)
	if err != nil {
		if os.IsNotExist(err) {
			return StatInfo{Path: abs, Exists: false}, nil
		}
		return StatInfo{}, err
	}
	return StatInfo{
		Path:    abs,
		Name:    info.Name(),
		Size:    info.Size(),
		Mode:    info.Mode().String(),
		IsDir:   info.IsDir(),
		ModTime: info.ModTime().UTC().Format("2006-01-02T15:04:05Z"),
		Exists:  true,
	}, nil
}

// ReadResult holds a (possibly partial) file read.
type ReadResult struct {
	Path       string `json:"path"`
	Content    string `json:"content"`
	StartLine  int    `json:"start_line,omitempty"`
	EndLine    int    `json:"end_line,omitempty"`
	TotalLines int    `json:"total_lines"`
	Bytes      int    `json:"bytes"`
	Truncated  bool   `json:"truncated,omitempty"`
	Encoding   string `json:"encoding"` // "utf-8" or "base64"
}

// Read reads a file. If startLine/endLine > 0, only that 1-indexed inclusive
// line range is returned. maxBytes caps content (0 = no cap). If the content is
// not valid UTF-8 it is returned base64-encoded.
func (f *FS) Read(abs string, startLine, endLine, maxBytes int) (ReadResult, error) {
	data, err := os.ReadFile(abs)
	if err != nil {
		return ReadResult{}, err
	}
	total := countLines(data)
	res := ReadResult{Path: abs, TotalLines: total, Encoding: "utf-8"}

	if startLine > 0 || endLine > 0 {
		sliced, s, e := sliceLines(data, startLine, endLine)
		data = sliced
		res.StartLine, res.EndLine = s, e
	}
	if maxBytes > 0 && len(data) > maxBytes {
		data = data[:maxBytes]
		res.Truncated = true
	}
	if isText(data) {
		res.Content = string(data)
	} else {
		res.Content = base64.StdEncoding.EncodeToString(data)
		res.Encoding = "base64"
	}
	res.Bytes = len(data)
	return res, nil
}

// Stream writes the file to w in chunks, optionally limited to a line range.
// It returns the number of bytes written.
func (f *FS) Stream(abs string, startLine, endLine int, w io.Writer) (int64, error) {
	file, err := os.Open(abs)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	if startLine <= 0 && endLine <= 0 {
		return io.Copy(w, file)
	}
	// Line-ranged streaming.
	var written int64
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	line := 0
	for scanner.Scan() {
		line++
		if startLine > 0 && line < startLine {
			continue
		}
		if endLine > 0 && line > endLine {
			break
		}
		n, err := w.Write(append(scanner.Bytes(), '\n'))
		written += int64(n)
		if err != nil {
			return written, err
		}
	}
	return written, scanner.Err()
}

// WriteMode controls how Write applies content.
type WriteMode string

const (
	Overwrite WriteMode = "overwrite"
	Append    WriteMode = "append"
	CreateNew WriteMode = "create" // fail if file exists
)

// WriteResult reports the outcome of a write.
type WriteResult struct {
	Path         string `json:"path"`
	BytesWritten int    `json:"bytes_written"`
	Created      bool   `json:"created"`
	Mode         string `json:"mode"`
}

// Write writes content to abs. If isBase64, content is decoded first. If
// mkdirs, parent directories are created.
func (f *FS) Write(abs, content string, mode WriteMode, mkdirs, isBase64 bool) (WriteResult, error) {
	var payload []byte
	if isBase64 {
		decoded, err := base64.StdEncoding.DecodeString(content)
		if err != nil {
			return WriteResult{}, fmt.Errorf("invalid base64: %w", err)
		}
		payload = decoded
	} else {
		payload = []byte(content)
	}

	_, statErr := os.Stat(abs)
	existed := statErr == nil

	if mode == CreateNew && existed {
		return WriteResult{}, fmt.Errorf("file already exists: %s", abs)
	}
	if mkdirs {
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			return WriteResult{}, err
		}
	}

	if mode == Append {
		file, err := os.OpenFile(abs, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return WriteResult{}, err
		}
		defer file.Close()
		n, err := file.Write(payload)
		if err != nil {
			return WriteResult{}, err
		}
		return WriteResult{Path: abs, BytesWritten: n, Created: !existed, Mode: string(mode)}, nil
	}

	if err := os.WriteFile(abs, payload, 0o644); err != nil {
		return WriteResult{}, err
	}
	return WriteResult{Path: abs, BytesWritten: len(payload), Created: !existed, Mode: string(mode)}, nil
}

// EditOp is a single search/replace edit.
type EditOp struct {
	Old        string `json:"old"`
	New        string `json:"new"`
	ReplaceAll bool   `json:"replace_all"`
}

// EditResult reports the outcome of an edit.
type EditResult struct {
	Path         string `json:"path"`
	Replacements int    `json:"replacements"`
	BytesWritten int    `json:"bytes_written"`
}

// Edit applies a sequence of search/replace edits to a file. For a
// non-replace-all op, the old string must appear exactly once (0 or >1 is an
// error) — this mirrors safe editor semantics.
func (f *FS) Edit(abs string, ops []EditOp) (EditResult, error) {
	data, err := os.ReadFile(abs)
	if err != nil {
		return EditResult{}, err
	}
	content := string(data)
	total := 0
	for i, op := range ops {
		if op.Old == "" {
			return EditResult{}, fmt.Errorf("edit %d: old string is empty", i)
		}
		count := strings.Count(content, op.Old)
		if count == 0 {
			return EditResult{}, fmt.Errorf("edit %d: old string not found", i)
		}
		if op.ReplaceAll {
			content = strings.ReplaceAll(content, op.Old, op.New)
			total += count
		} else {
			if count > 1 {
				return EditResult{}, fmt.Errorf("edit %d: old string is not unique (%d matches); set replace_all or add context", i, count)
			}
			content = strings.Replace(content, op.Old, op.New, 1)
			total++
		}
	}
	if err := os.WriteFile(abs, []byte(content), 0o644); err != nil {
		return EditResult{}, err
	}
	return EditResult{Path: abs, Replacements: total, BytesWritten: len(content)}, nil
}

// DirEntry is one item in a directory listing.
type DirEntry struct {
	Name  string `json:"name"`
	Path  string `json:"path"`
	IsDir bool   `json:"is_dir"`
	Size  int64  `json:"size"`
	Mode  string `json:"mode"`
}

// List lists a directory. If recursive, it descends up to maxDepth levels
// (maxDepth <= 0 means unlimited).
func (f *FS) List(abs string, recursive bool, maxDepth int) ([]DirEntry, error) {
	info, err := os.Stat(abs)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("not a directory: %s", abs)
	}
	var out []DirEntry
	if !recursive {
		entries, err := os.ReadDir(abs)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			ei, _ := e.Info()
			out = append(out, dirEntry(filepath.Join(abs, e.Name()), e.Name(), ei))
		}
		sortEntries(out)
		return out, nil
	}
	baseDepth := strings.Count(abs, string(os.PathSeparator))
	err = filepath.Walk(abs, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}
		if p == abs {
			return nil
		}
		if maxDepth > 0 {
			depth := strings.Count(p, string(os.PathSeparator)) - baseDepth
			if depth > maxDepth {
				if fi.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}
		out = append(out, dirEntry(p, fi.Name(), fi))
		return nil
	})
	sortEntries(out)
	return out, err
}

func dirEntry(path, name string, fi os.FileInfo) DirEntry {
	e := DirEntry{Name: name, Path: path}
	if fi != nil {
		e.IsDir = fi.IsDir()
		e.Size = fi.Size()
		e.Mode = fi.Mode().String()
	}
	return e
}

func sortEntries(e []DirEntry) {
	sort.Slice(e, func(i, j int) bool {
		if e[i].IsDir != e[j].IsDir {
			return e[i].IsDir // dirs first
		}
		return e[i].Path < e[j].Path
	})
}

func countLines(data []byte) int {
	if len(data) == 0 {
		return 0
	}
	n := 0
	for _, b := range data {
		if b == '\n' {
			n++
		}
	}
	if data[len(data)-1] != '\n' {
		n++
	}
	return n
}

func sliceLines(data []byte, start, end int) ([]byte, int, int) {
	lines := strings.SplitAfter(string(data), "\n")
	if start <= 0 {
		start = 1
	}
	if end <= 0 || end > len(lines) {
		end = len(lines)
	}
	if start > len(lines) {
		return []byte{}, start, end
	}
	return []byte(strings.Join(lines[start-1:end], "")), start, end
}

func isText(data []byte) bool {
	if len(data) == 0 {
		return true
	}
	// Treat as binary if it contains a NUL byte in the first 8KB.
	n := len(data)
	if n > 8192 {
		n = 8192
	}
	for i := 0; i < n; i++ {
		if data[i] == 0 {
			return false
		}
	}
	return true
}
