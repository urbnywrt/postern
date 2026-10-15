package store

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"time"
)

// The values of PublicPage.Unavailable: what the page does with a proxy that
// is paused, whose node is offline or whose probes fail.
const (
	PublicUnavailableHide = "hide" // the item is left out
	PublicUnavailableMark = "mark" // the item shows its name, its note and "unavailable"
)

// A PublicPage is the configuration of the public page (table public_page, one
// row) and its items, in order.
type PublicPage struct {
	Enabled       bool
	Host          string // the DNS name the page is served for, lower case, no port; "" for none
	Title         string // one line, or two: the second one is shown in the accent colour
	BodyMD        string
	Footer        string // plain text under the items; "" for the default text
	Unavailable   string // PublicUnavailableHide or PublicUnavailableMark
	NoIndex       bool
	DefaultLocale string // "ru" or "en"
	UpdatedAt     time.Time
	Items         []PublicPageItem
}

// A PublicPageItem is one proxy on the page.
type PublicPageItem struct {
	ProxyID    string
	PublicName string
	PublicNote string
	Code       string // 0 to 4 letters and digits, upper case; "" for the country of the server
}

// PublicPage returns the configuration of the page and its items, in order.
func (db *DB) PublicPage(ctx context.Context) (*PublicPage, error) {
	var (
		page             PublicPage
		enabled, noindex int64
		updated          int64
	)
	err := db.sql.QueryRowContext(ctx,
		`SELECT enabled, host, title, body_md, footer, unavailable, noindex, default_locale, updated_at FROM public_page WHERE id = 1`).
		Scan(&enabled, &page.Host, &page.Title, &page.BodyMD, &page.Footer, &page.Unavailable, &noindex, &page.DefaultLocale, &updated)
	if err != nil {
		return nil, fmt.Errorf("store: public page: %w", err)
	}
	page.Enabled, page.NoIndex = enabled != 0, noindex != 0
	if updated != 0 {
		page.UpdatedAt = timeFromDB(updated)
	}

	rows, err := db.sql.QueryContext(ctx,
		`SELECT proxy_id, public_name, public_note, code FROM public_page_items ORDER BY position`)
	if err != nil {
		return nil, fmt.Errorf("store: public page items: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var it PublicPageItem
		if err := rows.Scan(&it.ProxyID, &it.PublicName, &it.PublicNote, &it.Code); err != nil {
			return nil, fmt.Errorf("store: public page items: %w", err)
		}
		page.Items = append(page.Items, it)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: public page items: %w", err)
	}
	return &page, nil
}

// UpdatePublicPage stores p as the whole configuration of the page, items
// included, in one transaction: the row is updated, the items are deleted and
// then inserted in the order of p.Items (the unique index on position would
// refuse a row-by-row reorder). It sets p.UpdatedAt to the time of the write.
//
// An item whose proxy does not exist is [ErrNotFound], a proxy listed twice is
// [ErrConflict], and an Unavailable that is neither hide nor mark is an error;
// in every case nothing is changed. The caller has checked everything else.
func (db *DB) UpdatePublicPage(ctx context.Context, p *PublicPage) error {
	if p.Unavailable != PublicUnavailableHide && p.Unavailable != PublicUnavailableMark {
		return fmt.Errorf("store: update public page: unavailable is %q, want %q or %q",
			p.Unavailable, PublicUnavailableHide, PublicUnavailableMark)
	}
	now := normTime(db.now())
	err := db.withTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx,
			`UPDATE public_page SET enabled = ?, host = ?, title = ?, body_md = ?, footer = ?, unavailable = ?, noindex = ?,
			 default_locale = ?, updated_at = ? WHERE id = 1`,
			boolInt(p.Enabled), p.Host, p.Title, p.BodyMD, p.Footer, p.Unavailable, boolInt(p.NoIndex), p.DefaultLocale, now.Unix())
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM public_page_items`); err != nil {
			return err
		}
		for i, it := range p.Items {
			_, err := tx.ExecContext(ctx,
				`INSERT INTO public_page_items (proxy_id, position, public_name, public_note, code) VALUES (?, ?, ?, ?, ?)`,
				it.ProxyID, i, it.PublicName, it.PublicNote, it.Code)
			if err != nil {
				return mapErr(err, fkMissing)
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("store: update public page: %w", err)
	}
	p.UpdatedAt = now
	return nil
}

// MaxAdminHosts is how many names the panel remembers having served the admin
// pages on: the newest ones.
const MaxAdminHosts = 32

// settingAdminHosts is the key of the names in the table settings:
// [{"host":"","last_seen_unix":0}, ...], newest first.
const settingAdminHosts = "admin_hosts"

// An AdminHost is a name that an authenticated admin request carried as its
// Host, canonical (lower case, no port, no trailing dot), and when it was last
// seen. A public page is refused such a name.
type AdminHost struct {
	Host         string `json:"host"`
	LastSeenUnix int64  `json:"last_seen_unix"`
}

// AdminHosts returns the names the admin pages were served on, newest first.
func (db *DB) AdminHosts(ctx context.Context) ([]AdminHost, error) {
	var hosts []AdminHost
	if _, err := getSetting(ctx, db.sql, settingAdminHosts, &hosts); err != nil {
		return nil, err
	}
	return hosts, nil
}

// RecordAdminHost notes that the admin pages were served on host at seen. The
// name moves to the front of the list with that time, and the list is cut to
// the MaxAdminHosts newest names. The read and the write are one transaction.
func (db *DB) RecordAdminHost(ctx context.Context, host string, seen time.Time) error {
	err := db.withTx(ctx, func(tx *sql.Tx) error {
		var hosts []AdminHost
		if _, err := getSetting(ctx, tx, settingAdminHosts, &hosts); err != nil {
			return err
		}
		hosts = slices.DeleteFunc(hosts, func(h AdminHost) bool { return h.Host == host })
		hosts = append([]AdminHost{{Host: host, LastSeenUnix: seen.Unix()}}, hosts...)
		slices.SortStableFunc(hosts, func(a, b AdminHost) int {
			// Newest first; a tie keeps the order of the list, so the name that
			// was just seen, first in it, stays ahead of names seen the same
			// second before it.
			switch {
			case a.LastSeenUnix > b.LastSeenUnix:
				return -1
			case a.LastSeenUnix < b.LastSeenUnix:
				return 1
			}
			return 0
		})
		if len(hosts) > MaxAdminHosts {
			hosts = hosts[:MaxAdminHosts]
		}
		return putSetting(ctx, tx, settingAdminHosts, hosts)
	})
	if err != nil {
		return fmt.Errorf("store: record admin host: %w", err)
	}
	return nil
}
