package publicpage

import (
	"bytes"
	"html/template"
	"strconv"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/renderer"
	"github.com/yuin/goldmark/util"
)

// The Markdown of the page is rendered by goldmark (the stable v1 line, S6-2)
// with its safe defaults: raw HTML, inline and blocks, is replaced by a
// comment (html.WithUnsafe is never set). On top of them four renderers of
// this file replace goldmark's own, at a priority below the default's 1000,
// which registers them last:
//
//   - a link or an autolink is written with rel="nofollow noopener noreferrer",
//     and only when its destination passes safeDestination; otherwise its
//     text alone is written;
//   - an image is rendered as its alt text: the page loads nothing;
//   - headings are shifted one level down: the title is the only h1.
//
// goldmark's own link renderers check the destination after decoding it
// (GHSA-c97m-vxhj-p7j6, fixed in v1.7.17 and present in v1.8.6: before that
// the check ran on the raw bytes and "javascript&colon;" got through). The
// renderers here bypass goldmark's, so they decode for themselves, in the
// same order as goldmark (backslash escapes, numeric references, named
// entities), then drop every whitespace and control character, and check
// the result against an allowlist of schemes rather than a list of bad ones.
// What is written is that decoded form, percent- and HTML-escaped. The
// goldens and FuzzMarkdown guard this.
//
// Because rendering happens when the page is saved and at start, not per
// request, the converter is shared under a lock.
var (
	mdMu sync.Mutex
	md   = goldmark.New(goldmark.WithRendererOptions(
		renderer.WithNodeRenderers(util.Prioritized(pageRenderer{}, 500)),
	))
)

// linkRel is the rel of every link of the Markdown: a search engine does not
// follow it, and the page it opens gets neither this window nor the referrer.
const linkRel = ` rel="nofollow noopener noreferrer"`

// renderMarkdown renders the Markdown of the page to HTML.
func renderMarkdown(src string) template.HTML {
	mdMu.Lock()
	defer mdMu.Unlock()
	var buf bytes.Buffer
	if err := md.Convert([]byte(src), &buf); err != nil {
		return "" // a bytes.Buffer never fails; nothing is better than half a page
	}
	return template.HTML(buf.String()) //nolint:gosec // goldmark's output, raw HTML omitted and link schemes allowlisted
}

// pageRenderer registers the four renderers of this file.
type pageRenderer struct{}

func (pageRenderer) RegisterFuncs(reg renderer.NodeRendererFuncRegisterer) {
	reg.Register(ast.KindLink, renderLink)
	reg.Register(ast.KindAutoLink, renderAutoLink)
	reg.Register(ast.KindImage, renderImage)
	reg.Register(ast.KindHeading, renderHeading)
}

// renderLink renders [text](dest): an <a> with the rel, or the text alone when
// the destination is not allowed.
func renderLink(w util.BufWriter, _ []byte, node ast.Node, entering bool) (ast.WalkStatus, error) {
	dest, ok := safeDestination(node.(*ast.Link).Destination)
	if !ok {
		return ast.WalkContinue, nil
	}
	if entering {
		writeAnchorStart(w, dest)
	} else {
		_, _ = w.WriteString("</a>")
	}
	return ast.WalkContinue, nil
}

// renderAutoLink renders <https://...> and <user@example.com>: an <a> with the
// rel, or the text alone when the destination is not allowed.
func renderAutoLink(w util.BufWriter, source []byte, node ast.Node, entering bool) (ast.WalkStatus, error) {
	if !entering {
		return ast.WalkContinue, nil
	}
	n := node.(*ast.AutoLink)
	url := n.URL(source)
	if n.AutoLinkType == ast.AutoLinkEmail && !bytes.HasPrefix(bytes.ToLower(url), []byte("mailto:")) {
		url = append([]byte("mailto:"), url...)
	}
	label := util.EscapeHTML(n.Label(source))
	dest, ok := safeDestination(url)
	if !ok {
		_, _ = w.Write(label)
		return ast.WalkContinue, nil
	}
	writeAnchorStart(w, dest)
	_, _ = w.Write(label)
	_, _ = w.WriteString("</a>")
	return ast.WalkContinue, nil
}

// writeAnchorStart writes <a href="dest" rel="..."> for a destination that
// safeDestination allowed, percent-escaped (without decoding it again) and
// escaped for the attribute.
func writeAnchorStart(w util.BufWriter, dest []byte) {
	_, _ = w.WriteString(`<a href="`)
	_, _ = w.Write(util.EscapeHTML(util.URLEscape(dest, false)))
	_, _ = w.WriteString(`"` + linkRel + `>`)
}

// renderImage renders ![alt](src) as the alt text: its children, which are the
// inline nodes of the alt text, are rendered as they would be anywhere else,
// and no <img> is written.
func renderImage(util.BufWriter, []byte, ast.Node, bool) (ast.WalkStatus, error) {
	return ast.WalkContinue, nil
}

// renderHeading renders a heading one level down: # is <h2>, ###### stays
// <h6>.
func renderHeading(w util.BufWriter, _ []byte, node ast.Node, entering bool) (ast.WalkStatus, error) {
	level := strconv.Itoa(min(node.(*ast.Heading).Level+1, 6))
	if entering {
		_, _ = w.WriteString("<h" + level + ">")
	} else {
		_, _ = w.WriteString("</h" + level + ">\n")
	}
	return ast.WalkContinue, nil
}

// safeDestination decodes a link destination as goldmark's renderer would
// (backslash escapes, numeric references, named entities), drops every
// whitespace and control character, and reports whether what is left may be
// linked: a reference with no scheme (relative), or one whose scheme is
// http, https, mailto or tg. Everything else, javascript:, vbscript:, data:,
// file: and schemes nobody asked for, is refused. The decoded form is what
// the caller writes, so that no later decoding can change the scheme.
func safeDestination(raw []byte) ([]byte, bool) {
	dest := util.ResolveEntityNames(util.ResolveNumericReferences(util.UnescapePunctuations(raw)))
	clean := make([]byte, 0, len(dest))
	for i := 0; i < len(dest); {
		r, size := utf8.DecodeRune(dest[i:])
		if (r != utf8.RuneError || size > 1) && (unicode.IsSpace(r) || unicode.IsControl(r)) {
			i += size
			continue
		}
		clean = append(clean, dest[i:i+size]...)
		i += size
	}
	scheme, has := schemeOf(clean)
	if !has {
		return clean, true
	}
	switch string(bytes.ToLower(scheme)) {
	case "http", "https", "mailto", "tg":
		return clean, true
	}
	return clean, false
}

// schemeOf returns the scheme of a reference as RFC 3986 reads it: a letter,
// then letters, digits, "+", "-" and ".", then ":". A reference whose first
// run of such bytes ends in anything else, or that has no such run, has no
// scheme and is relative.
func schemeOf(ref []byte) ([]byte, bool) {
	if len(ref) == 0 || !isAlpha(ref[0]) {
		return nil, false
	}
	for i := 1; i < len(ref); i++ {
		c := ref[i]
		switch {
		case c == ':':
			return ref[:i], true
		case isAlpha(c), '0' <= c && c <= '9', c == '+', c == '-', c == '.':
		default:
			return nil, false
		}
	}
	return nil, false
}

func isAlpha(c byte) bool { return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' }
