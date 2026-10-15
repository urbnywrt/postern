// Package site generates the decoy site of a WEB proxy: a small static site
// that telemt serves (decoy.mode = "static_directory") for every request of
// the vhost that is not the proxy's. It is deterministic in its seed, the
// proxy id, so that every generation of the instance gets the same site and
// nothing has to be stored: the same seed gives the same files, byte for byte.
//
// Sites differ in their kind of business, name, palette, layout, pages and
// text. Every page uses one external style sheet and nothing else: no inline
// script or style, no fonts, images or anything fetched from a third party,
// which a client could be made to reach. The site has its own 404 page.
package site

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"html"
	"math/rand/v2"
	"strings"
)

// The files every site has; the other pages are named by the generator.
const (
	IndexFile    = "index.html"
	StyleFile    = "styles.css"
	NotFoundFile = "404.html"
)

// Generate returns the files of the decoy site of seed, by name: IndexFile,
// two to four more pages, StyleFile and NotFoundFile.
func Generate(seed string) map[string][]byte {
	sum := sha256.Sum256([]byte("postern-decoy-site-v1\x00" + seed))
	// Not a secret: the generator must give the same site for the same seed,
	// which is the whole point; nothing here is random in a security sense.
	rng := rand.New(rand.NewPCG(binary.BigEndian.Uint64(sum[:8]), binary.BigEndian.Uint64(sum[8:16]))) //nolint:gosec // deterministic by design
	s := newSite(rng)
	files := map[string][]byte{StyleFile: []byte(s.css())}
	for _, p := range s.pages {
		files[p.file] = []byte(s.render(p))
	}
	files[NotFoundFile] = []byte(s.render(page{file: NotFoundFile, title: "Page not found", kind: pageNotFound}))
	return files
}

// ---- the model ----------------------------------------------------------------

type pageKind int

const (
	pageIndex pageKind = iota
	pageAbout
	pageServices
	pageGallery
	pageContact
	pageNews
	pageFAQ
	pageNotFound
)

type page struct {
	file  string
	title string
	kind  pageKind
}

type site struct {
	rng       *rand.Rand
	arch      archetype
	name      string
	tagline   string
	town      string
	founded   int
	layout    int // 0 top nav, 1 side nav, 2 centred
	palette   palette
	fontStack string
	radius    int
	pages     []page
}

type archetype struct {
	kind      string
	names     []string
	taglines  []string
	services  []string
	about     []string
	faq       [][2]string
	newsItems []string
}

type palette struct {
	bg, fg, accent, muted, card string
}

func newSite(rng *rand.Rand) *site {
	s := &site{rng: rng}
	s.arch = archetypes[rng.IntN(len(archetypes))]
	first := pick(rng, firstWords)
	s.name = first + " " + pick(rng, s.arch.names)
	s.town = pick(rng, towns)
	s.founded = 1987 + rng.IntN(35)
	s.tagline = s.fill(pick(rng, s.arch.taglines))
	s.layout = rng.IntN(3)
	s.palette = palettes[rng.IntN(len(palettes))]
	s.fontStack = pick(rng, fontStacks)
	s.radius = []int{0, 2, 4, 6, 8, 12}[rng.IntN(6)]

	s.pages = []page{{IndexFile, "Home", pageIndex}}
	extra := []page{
		{"about.html", "About", pageAbout},
		{"services.html", pick(rng, []string{"Services", "What we do", "Offer"}), pageServices},
		{"gallery.html", pick(rng, []string{"Gallery", "Work", "Portfolio"}), pageGallery},
		{"contact.html", pick(rng, []string{"Contact", "Visit", "Find us"}), pageContact},
		{"news.html", pick(rng, []string{"News", "Journal", "Updates"}), pageNews},
		{"faq.html", "FAQ", pageFAQ},
	}
	rng.Shuffle(len(extra), func(i, j int) { extra[i], extra[j] = extra[j], extra[i] })
	n := 2 + rng.IntN(3) // 2 to 4 more pages: 3 to 5 in all
	s.pages = append(s.pages, extra[:n]...)
	return s
}

func pick[T any](rng *rand.Rand, xs []T) T { return xs[rng.IntN(len(xs))] }

// ---- rendering ----------------------------------------------------------------

func (s *site) render(p page) string {
	var b strings.Builder
	esc := html.EscapeString
	b.WriteString("<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n")
	b.WriteString("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n")
	fmt.Fprintf(&b, "<title>%s - %s</title>\n", esc(p.title), esc(s.name))
	b.WriteString("<link rel=\"stylesheet\" href=\"" + StyleFile + "\">\n</head>\n")
	fmt.Fprintf(&b, "<body class=\"layout-%d\">\n", s.layout)
	b.WriteString("<header class=\"site-header\">\n")
	fmt.Fprintf(&b, "<a class=\"brand\" href=\"%s\">%s</a>\n", IndexFile, esc(s.name))
	b.WriteString("<nav class=\"site-nav\">\n<ul>\n")
	for _, q := range s.pages {
		cls := ""
		if q.file == p.file {
			cls = " class=\"current\""
		}
		fmt.Fprintf(&b, "<li><a%s href=\"%s\">%s</a></li>\n", cls, q.file, esc(q.title))
	}
	b.WriteString("</ul>\n</nav>\n</header>\n<main class=\"content\">\n")
	s.body(&b, p)
	b.WriteString("</main>\n<footer class=\"site-footer\">\n")
	fmt.Fprintf(&b, "<p>%s, %s. Established %d.</p>\n", esc(s.name), esc(s.town), s.founded)
	b.WriteString("</footer>\n</body>\n</html>\n")
	return b.String()
}

func (s *site) body(b *strings.Builder, p page) {
	esc := html.EscapeString
	// The text of a page is drawn from the site's generator so that the same
	// site always has the same pages; a fresh generator per page would make
	// the pages depend on their order.
	rng := s.rng
	switch p.kind {
	case pageIndex:
		fmt.Fprintf(b, "<section class=\"hero\">\n<h1>%s</h1>\n<p class=\"lead\">%s</p>\n</section>\n", esc(s.name), esc(s.tagline))
		b.WriteString("<section class=\"cards\">\n")
		for _, svc := range sample(rng, s.arch.services, 3) {
			fmt.Fprintf(b, "<article class=\"card\">\n<h2>%s</h2>\n<p>%s</p>\n</article>\n", esc(svc), esc(pick(rng, blurbs)))
		}
		b.WriteString("</section>\n")
	case pageAbout:
		fmt.Fprintf(b, "<h1>About %s</h1>\n", esc(s.name))
		for _, para := range sample(rng, s.arch.about, 2) {
			fmt.Fprintf(b, "<p>%s</p>\n", esc(s.fill(para)))
		}
	case pageServices:
		fmt.Fprintf(b, "<h1>%s</h1>\n<ul class=\"services\">\n", esc(p.title))
		for _, svc := range sample(rng, s.arch.services, 4) {
			fmt.Fprintf(b, "<li><strong>%s</strong> - %s</li>\n", esc(svc), esc(pick(rng, blurbs)))
		}
		b.WriteString("</ul>\n")
	case pageGallery:
		fmt.Fprintf(b, "<h1>%s</h1>\n<div class=\"grid\">\n", esc(p.title))
		for i := range 4 + rng.IntN(5) {
			fmt.Fprintf(b, "<figure class=\"tile tile-%d\"><figcaption>%s</figcaption></figure>\n", i%4, esc(pick(rng, captions)))
		}
		b.WriteString("</div>\n")
	case pageContact:
		fmt.Fprintf(b, "<h1>%s</h1>\n", esc(p.title))
		fmt.Fprintf(b, "<p>We are in %s. %s</p>\n", esc(s.town), esc(pick(rng, visiting)))
		fmt.Fprintf(b, "<p>%s</p>\n", esc(pick(rng, hours)))
	case pageNews:
		fmt.Fprintf(b, "<h1>%s</h1>\n", esc(p.title))
		year := 2019 + rng.IntN(5)
		for i, item := range sample(rng, s.arch.newsItems, 3) {
			fmt.Fprintf(b, "<article class=\"post\">\n<h2>%s</h2>\n<p class=\"date\">%s %d</p>\n<p>%s</p>\n</article>\n",
				esc(item), months[(i*3+rng.IntN(3))%12], year+i/2, esc(pick(rng, blurbs)))
		}
	case pageFAQ:
		b.WriteString("<h1>Frequently asked questions</h1>\n<dl class=\"faq\">\n")
		for _, qa := range sampleQA(rng, s.arch.faq, 3) {
			fmt.Fprintf(b, "<dt>%s</dt>\n<dd>%s</dd>\n", esc(qa[0]), esc(qa[1]))
		}
		b.WriteString("</dl>\n")
	case pageNotFound:
		fmt.Fprintf(b, "<h1>Page not found</h1>\n<p>There is no such page on this site. <a href=\"%s\">Back to the front page</a>.</p>\n", IndexFile)
	}
}

// fill substitutes the placeholders of the material: {town} and {year}.
func (s *site) fill(text string) string {
	return strings.NewReplacer("{town}", s.town, "{year}", fmt.Sprint(s.founded)).Replace(text)
}

func sample[T any](rng *rand.Rand, xs []T, n int) []T {
	idx := rng.Perm(len(xs))
	n = min(n, len(xs))
	out := make([]T, 0, n)
	for _, i := range idx[:n] {
		out = append(out, xs[i])
	}
	return out
}

func sampleQA(rng *rand.Rand, xs [][2]string, n int) [][2]string { return sample(rng, xs, n) }

func (s *site) css() string {
	p := s.palette
	var b strings.Builder
	fmt.Fprintf(&b, ":root { --bg: %s; --fg: %s; --accent: %s; --muted: %s; --card: %s; --radius: %dpx; }\n", p.bg, p.fg, p.accent, p.muted, p.card, s.radius)
	b.WriteString("* { box-sizing: border-box; }\n")
	fmt.Fprintf(&b, "body { margin: 0; font-family: %s; color: var(--fg); background: var(--bg); line-height: %.2f; }\n", s.fontStack, 1.45+float64(s.rng.IntN(4))*0.05)
	b.WriteString("a { color: var(--accent); }\n")
	b.WriteString(".site-header { display: flex; align-items: center; justify-content: space-between; padding: 1rem 2rem; border-bottom: 1px solid var(--muted); }\n")
	b.WriteString(".brand { font-weight: 700; text-decoration: none; font-size: 1.25rem; color: var(--fg); }\n")
	b.WriteString(".site-nav ul { list-style: none; display: flex; gap: 1rem; margin: 0; padding: 0; }\n")
	b.WriteString(".site-nav a { text-decoration: none; }\n.site-nav .current { font-weight: 700; }\n")
	switch s.layout {
	case 0:
		fmt.Fprintf(&b, ".content { max-width: %dpx; margin: 0 auto; padding: 2rem; }\n", 880+40*s.rng.IntN(5))
	case 1:
		b.WriteString(".layout-1 { display: grid; grid-template-columns: 220px 1fr; min-height: 100vh; }\n")
		b.WriteString(".layout-1 .site-header { grid-row: 1 / span 2; flex-direction: column; align-items: flex-start; border-bottom: 0; border-right: 1px solid var(--muted); }\n")
		b.WriteString(".layout-1 .site-nav ul { flex-direction: column; margin-top: 2rem; }\n")
		b.WriteString(".layout-1 .content { padding: 2rem 3rem; }\n.layout-1 .site-footer { grid-column: 2; }\n")
	default:
		fmt.Fprintf(&b, ".layout-2 .content { max-width: %dpx; margin: 0 auto; padding: 3rem 1.5rem; text-align: center; }\n", 640+40*s.rng.IntN(4))
		b.WriteString(".layout-2 .site-header { flex-direction: column; gap: 0.75rem; }\n")
	}
	b.WriteString(".hero h1 { font-size: 2.4rem; margin-bottom: 0.25rem; }\n.lead { font-size: 1.2rem; color: var(--muted); }\n")
	b.WriteString(".cards, .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1.25rem; margin-top: 2rem; }\n")
	b.WriteString(".card, .post { background: var(--card); border-radius: var(--radius); padding: 1.25rem; }\n")
	b.WriteString(".tile { margin: 0; aspect-ratio: 4 / 3; border-radius: var(--radius); display: flex; align-items: flex-end; padding: 0.75rem; color: var(--bg); }\n")
	b.WriteString(".tile-0 { background: var(--accent); }\n.tile-1 { background: var(--muted); }\n.tile-2 { background: var(--fg); }\n.tile-3 { background: var(--card); color: var(--fg); }\n")
	b.WriteString(".services li { margin: 0.5rem 0; }\n.faq dt { font-weight: 700; margin-top: 1rem; }\n.date { color: var(--muted); font-size: 0.9rem; }\n")
	b.WriteString(".site-footer { padding: 1.5rem 2rem; border-top: 1px solid var(--muted); color: var(--muted); font-size: 0.9rem; }\n")
	return b.String()
}

// ---- the material -------------------------------------------------------------

var firstWords = []string{"Northgate", "Maple", "Harbour", "Linden", "Oakfield", "Riverside", "Westbrook", "Hillcrest", "Birch", "Meadow", "Stonebridge", "Elmwood", "Lantern", "Copper", "Juniper", "Willow"}

var towns = []string{"the old town", "the harbour district", "the north end", "the market quarter", "the valley", "the east side", "the mill district", "the lakeside"}

var fontStacks = []string{
	"Georgia, 'Times New Roman', serif",
	"system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif",
	"'Helvetica Neue', Helvetica, Arial, sans-serif",
	"'Palatino Linotype', Palatino, serif",
	"Verdana, Geneva, sans-serif",
	"'Trebuchet MS', sans-serif",
}

var palettes = []palette{
	{"#fdfcf8", "#1f2328", "#b5541c", "#7a7368", "#f1ede4"},
	{"#ffffff", "#222222", "#1f5fa8", "#6b7785", "#eef3f9"},
	{"#f4f7f5", "#14301f", "#2f7d4f", "#5f7466", "#e3ece6"},
	{"#1b1d22", "#e8e6e1", "#e0a84a", "#9a968d", "#262930"},
	{"#fff8f0", "#3b2a1e", "#c1543a", "#8c7b6b", "#f7e9db"},
	{"#f6f6f9", "#23203a", "#6c4fd6", "#7b7890", "#ebe9f5"},
	{"#fafafa", "#101010", "#0b7a75", "#707070", "#ececec"},
	{"#102a43", "#f0f4f8", "#f0b429", "#9fb3c8", "#1c3d5a"},
	{"#fffdf7", "#2a2a2a", "#8a1c3b", "#7d7368", "#f5efe3"},
}

var blurbs = []string{
	"Small batches, careful work and no shortcuts.",
	"We take the time to get the details right.",
	"Honest advice first; everything else follows from it.",
	"Made to last, and repaired when it does not.",
	"Appointments are relaxed and never rushed.",
	"Local materials wherever they are good enough, which is almost always.",
	"Clear prices, agreed before the work begins.",
	"A quiet place to think, look and ask questions.",
}

var captions = []string{"Spring collection", "Workshop, early morning", "Detail of the finish", "Before and after", "The front room", "On the bench", "Autumn series", "Commissioned piece", "Open day"}

var visiting = []string{
	"Visits are by appointment on weekdays and open to all on Saturday mornings.",
	"The door is open whenever the lights are on; ring the bell otherwise.",
	"Street parking is easy after ten; the bus stops at the corner.",
	"Come in through the courtyard, past the bicycles.",
}

var hours = []string{
	"Tuesday to Friday 10:00 to 18:00, Saturday 10:00 to 14:00.",
	"Monday to Saturday 9:00 to 17:30. Closed on public holidays.",
	"Wednesday to Sunday 11:00 to 19:00.",
	"Weekdays 8:30 to 16:30, or later by arrangement.",
}

var months = []string{"January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"}

var archetypes = []archetype{
	{
		kind:     "bakery",
		names:    []string{"Bakery", "Bakehouse", "Bread Company", "Patisserie"},
		taglines: []string{"Bread the slow way, every morning.", "Sourdough, pastries and good coffee.", "Baked before dawn, gone by noon."},
		services: []string{"Sourdough loaves", "Morning pastries", "Celebration cakes", "Wholesale for cafes", "Baking classes", "Seasonal specials"},
		about: []string{
			"We opened our ovens in {town} in {year} with a single mixer and a borrowed recipe for a country loaf.",
			"Everything is made by hand from flour milled within a day's drive, and the starter has been alive since the first week.",
			"The shop has grown, the bread has not changed, and we still sell out most days.",
		},
		faq: [][2]string{
			{"Do you take orders for cakes?", "Yes, with a week's notice for anything decorated."},
			{"Is there a gluten-free option?", "We bake a buckwheat loaf on Fridays; it shares the kitchen with wheat."},
			{"When is the bread ready?", "The first loaves come out around half past seven."},
			{"Do you deliver?", "Only to the cafes we supply; everyone else is welcome to collect."},
		},
		newsItems: []string{"New rye loaf on Thursdays", "Summer opening hours", "Classes return in the autumn", "A second oven arrives", "Holiday orders now open"},
	},
	{
		kind:     "studio",
		names:    []string{"Architecture Studio", "Design Office", "Studio", "Atelier"},
		taglines: []string{"Buildings that age well.", "Thoughtful spaces for ordinary life.", "Design, drawn with care."},
		services: []string{"Residential design", "Renovations and extensions", "Interior planning", "Feasibility studies", "Planning applications", "Site supervision"},
		about: []string{
			"The studio was founded in {year} and has worked from the same light-filled rooms in {town} ever since.",
			"We prefer modest projects done well to large ones done quickly, and most of our clients come by recommendation.",
			"Every project begins with a long conversation and a walk around the site.",
		},
		faq: [][2]string{
			{"Do you take on small projects?", "Yes; a single room is a project like any other."},
			{"How long does a design take?", "Usually two to four months from the first meeting to drawings."},
			{"Do you work outside the region?", "Occasionally, when the project is a good fit."},
			{"What does the first meeting cost?", "Nothing; it is how we both find out whether to go on."},
		},
		newsItems: []string{"Courtyard house completed", "Open studio evening", "A talk on timber construction", "New member of the team", "Published in a regional review"},
	},
	{
		kind:     "pottery",
		names:    []string{"Pottery", "Ceramics", "Clay Workshop", "Kiln Room"},
		taglines: []string{"Functional ceramics, thrown by hand.", "Cups, bowls and plates for every day.", "Clay, glaze and patience."},
		services: []string{"Tableware", "Commissions", "Evening classes", "Open studio days", "Glaze consultation", "Firing service"},
		about: []string{
			"The workshop started in a garage in {town} in {year} and moved into the old dairy three years later.",
			"We throw in small series, fire twice and glaze with recipes we mix ourselves.",
			"Nothing leaves the shelves until it has been used at our own table.",
		},
		faq: [][2]string{
			{"Is the ware dishwasher safe?", "Yes, all of it; the glazes are fired to stoneware temperature."},
			{"Can I book a single class?", "Taster sessions run on the first Saturday of the month."},
			{"Do you ship?", "Within the country, carefully packed."},
			{"Can I visit the workshop?", "Open days are listed on the news page."},
		},
		newsItems: []string{"Autumn glaze tests", "Open studio weekend", "New tumbler series", "Kiln rebuilt", "Winter classes announced"},
	},
	{
		kind:     "bookshop",
		names:    []string{"Books", "Bookshop", "Booksellers", "Reading Room"},
		taglines: []string{"An independent bookshop since {year}.", "Good books, chosen by hand.", "Browse slowly."},
		services: []string{"New and secondhand books", "Special orders", "Reading groups", "Author evenings", "Gift wrapping", "School supply"},
		about: []string{
			"The shop opened in {town} in {year} with two rooms of secondhand books and a kettle.",
			"We still choose every title ourselves, and the kettle is still on.",
			"Our reading groups meet on weekday evenings and are open to anyone who has read the book.",
		},
		faq: [][2]string{
			{"Can you order a book I cannot find?", "Almost always, within a few days."},
			{"Do you buy secondhand books?", "Yes, on weekday mornings; bring them in a bag we can carry."},
			{"Is there somewhere to sit?", "Two armchairs upstairs, first come first served."},
			{"Do you sell gift vouchers?", "Yes, in any amount."},
		},
		newsItems: []string{"Poetry evening in the back room", "New arrivals this week", "Summer reading list", "Children's hour returns", "Shop closed for stocktaking"},
	},
	{
		kind:     "garden",
		names:    []string{"Garden Design", "Nursery", "Landscapes", "Plant Nursery"},
		taglines: []string{"Gardens for the climate we have.", "Hardy plants, grown here.", "Planting that gets better each year."},
		services: []string{"Garden design", "Planting plans", "Hardy perennials", "Hedging and trees", "Maintenance visits", "Advice by the hour"},
		about: []string{
			"We began growing perennials in {town} in {year} and still propagate most of what we sell.",
			"The design work came later, when customers kept asking what to do with the plants they had bought.",
			"Our gardens are planted densely, watered little and left to find their own balance.",
		},
		faq: [][2]string{
			{"When is the nursery open?", "From March to October; the design office all year."},
			{"Do you do lawns?", "Rarely; we prefer meadows."},
			{"Can you work with an existing garden?", "That is most of what we do."},
			{"Do you deliver plants?", "Yes, locally, on Thursdays."},
		},
		newsItems: []string{"Spring plant list", "A new border at the station", "Dry garden open day", "Bare-root season begins", "Workshop on pruning"},
	},
	{
		kind:     "music",
		names:    []string{"Music School", "Piano Studio", "Music Rooms", "Conservatoire"},
		taglines: []string{"Lessons for every age and every pace.", "Learn an instrument properly.", "Music, taught with patience."},
		services: []string{"Piano lessons", "Strings", "Theory and aural", "Ensemble evenings", "Exam preparation", "Instrument hire"},
		about: []string{
			"The school opened in {town} in {year} with one piano and three pupils.",
			"Today a dozen teachers work in six rooms, and the concerts fill the hall twice a year.",
			"We teach children and adults alike, beginners and returners, and nobody is too old to start.",
		},
		faq: [][2]string{
			{"Do I need my own instrument?", "For piano, access to one to practise on; others can be hired."},
			{"How long is a lesson?", "Thirty, forty-five or sixty minutes."},
			{"Do you prepare for exams?", "Yes, when the pupil wants to take them."},
			{"Are there adult groups?", "An ensemble meets on Wednesday evenings."},
		},
		newsItems: []string{"Summer concert", "New cello teacher", "Theory course for adults", "Hall repainted", "Term dates published"},
	},
}
