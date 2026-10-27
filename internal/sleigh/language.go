package sleigh

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strconv"
)

// ErrUnknownLanguage is returned for a language id no .ldefs file defines,
// or whose compiled spec is not vendored.
var ErrUnknownLanguage = errors.New("unknown language")

// LanguageInfo describes one language from a Ghidra .ldefs file.
type LanguageInfo struct {
	ID          string // processor:endian:size:variant, e.g. ARM:LE:32:v8
	Processor   string
	BigEndian   bool
	Size        int
	Variant     string
	Description string
	slaPath     string
	pspecPath   string
}

// Language is a loaded spec plus the context defaults from its .pspec.
type Language struct {
	LanguageInfo
	Spec     *Spec
	defaults []contextDefault
}

type contextDefault struct {
	name string
	val  uint32
}

type ldefsFile struct {
	Languages []struct {
		ID          string `xml:"id,attr"`
		Processor   string `xml:"processor,attr"`
		Endian      string `xml:"endian,attr"`
		Size        int    `xml:"size,attr"`
		Variant     string `xml:"variant,attr"`
		SlaFile     string `xml:"slafile,attr"`
		Pspec       string `xml:"processorspec,attr"`
		Description string `xml:"description"`
	} `xml:"language"`
}

type pspecFile struct {
	ContextSets []struct {
		Sets []struct {
			Name string `xml:"name,attr"`
			Val  string `xml:"val,attr"`
		} `xml:"set"`
	} `xml:"context_data>context_set"`
}

// Languages lists every language whose compiled spec is present in fsys,
// which uses Ghidra's Processors/<arch>/data/languages layout.
func Languages(fsys fs.FS) ([]LanguageInfo, error) {
	files, err := fs.Glob(fsys, "Processors/*/data/languages/*.ldefs")
	if err != nil {
		return nil, err
	}
	var out []LanguageInfo
	for _, f := range files {
		data, err := fs.ReadFile(fsys, f)
		if err != nil {
			return nil, err
		}
		var defs ldefsFile
		if err := xml.Unmarshal(stripProlog(data), &defs); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		dir := path.Dir(f)
		for _, l := range defs.Languages {
			info := LanguageInfo{
				ID:          l.ID,
				Processor:   l.Processor,
				BigEndian:   l.Endian == "big",
				Size:        l.Size,
				Variant:     l.Variant,
				Description: l.Description,
				slaPath:     path.Join(dir, l.SlaFile),
				pspecPath:   path.Join(dir, l.Pspec),
			}
			if _, err := fs.Stat(fsys, info.slaPath); err != nil {
				continue // spec not vendored
			}
			out = append(out, info)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// LoadLanguage loads the language with the given id from fsys.
func LoadLanguage(fsys fs.FS, id string) (*Language, error) {
	infos, err := Languages(fsys)
	if err != nil {
		return nil, err
	}
	for _, info := range infos {
		if info.ID == id {
			return loadLanguage(fsys, info)
		}
	}
	return nil, fmt.Errorf("%w: %s", ErrUnknownLanguage, id)
}

func loadLanguage(fsys fs.FS, info LanguageInfo) (*Language, error) {
	sla, err := fs.ReadFile(fsys, info.slaPath)
	if err != nil {
		return nil, err
	}
	spec, err := LoadSpec(sla)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", info.slaPath, err)
	}
	l := &Language{LanguageInfo: info, Spec: spec}
	data, err := fs.ReadFile(fsys, info.pspecPath)
	if err != nil {
		return nil, err
	}
	var ps pspecFile
	if err := xml.Unmarshal(stripProlog(data), &ps); err != nil {
		return nil, fmt.Errorf("%s: %w", info.pspecPath, err)
	}
	for _, cs := range ps.ContextSets {
		for _, s := range cs.Sets {
			v, err := strconv.ParseUint(s.Val, 0, 32)
			if err != nil {
				return nil, fmt.Errorf("%s: context %s: %w", info.pspecPath, s.Name, err)
			}
			if spec.ContextVar(s.Name) == nil {
				return nil, fmt.Errorf("%s: unknown context variable %s", info.pspecPath, s.Name)
			}
			l.defaults = append(l.defaults, contextDefault{s.Name, uint32(v)})
		}
	}
	return l, nil
}

// stripProlog drops a leading <?xml ...?> declaration. Some Ghidra files
// declare XML 1.1, which encoding/xml rejects although their content is
// plain 1.0.
func stripProlog(data []byte) []byte {
	trimmed := bytes.TrimLeft(data, " \t\r\n\ufeff")
	if bytes.HasPrefix(trimmed, []byte("<?xml")) {
		if i := bytes.Index(trimmed, []byte("?>")); i >= 0 {
			return trimmed[i+2:]
		}
	}
	return data
}

// NewDecoder returns a decoder over mem with the language's default
// context.
func (l *Language) NewDecoder(mem Memory) *Decoder {
	d := NewDecoder(l.Spec, mem)
	for _, c := range l.defaults {
		// Names were checked when the language loaded.
		_ = d.SetContextDefault(c.name, c.val)
	}
	return d
}
