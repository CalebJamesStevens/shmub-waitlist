package main

import (
	"context"
	"embed"
	"encoding/json"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed static/*
var staticFS embed.FS

type server struct {
	db     *pgxpool.Pool
	origin string
}

type waitlistReq struct {
	Email    string `json:"email"`
	Honeypot string `json:"website"`
	Source   string `json:"source"`
}

var emailRe = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)

func main() {
	port := getenv("PORT", "3000")
	dsn := os.Getenv("DATABASE_URL")
	if strings.TrimSpace(dsn) == "" {
		log.Fatal("DATABASE_URL is required")
	}

	origin := strings.TrimSpace(os.Getenv("ORIGIN"))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		log.Fatalf("db connect failed: %v", err)
	}
	defer pool.Close()

	if err := migrate(ctx, pool); err != nil {
		log.Fatalf("db migrate failed: %v", err)
	}

	s := &server{db: pool, origin: origin}

	// Embedded static FS
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		log.Fatalf("static fs sub failed: %v", err)
	}
	fileServer := http.FileServer(http.FS(sub))
	static := withCache(withContentTypes(fileServer))

	mux := http.NewServeMux()

	// API
	mux.HandleFunc("/healthz", s.healthz)
	mux.HandleFunc("/api/waitlist", s.waitlist)

	// Serve /static/* (if any old links still use that)
	mux.Handle("/static/", http.StripPrefix("/static/", static))

	// Serve assets at root, but handle homepage explicitly (no FileServer redirect loops)
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path

		// Normalize weird root variants that cause FileServer to 301 -> "./"
		if p == "" || p == "/" || p == "." || p == "./" || p == "/." || p == "/./" {
			// Serve index.html explicitly
			b, err := staticFS.ReadFile("static/index.html")
			if err != nil {
				http.Error(w, "missing index.html", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "public, max-age=300")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(b)
			return
		}

		// Clean path to avoid oddities like //, /./ etc
		clean := path.Clean("/" + strings.TrimPrefix(p, "/"))
		r2 := r.Clone(r.Context())
		r2.URL.Path = clean

		static.ServeHTTP(w, r2)
	}))

	h := withSecurityHeaders(mux)

	log.Printf("listening on :%s", port)
	if err := http.ListenAndServe(":"+port, h); err != nil {
		log.Fatal(err)
	}
}

func withCache(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".css") {
			w.Header().Set("Cache-Control", "public, max-age=604800, immutable")
		} else {
			w.Header().Set("Cache-Control", "public, max-age=300")
		}
		next.ServeHTTP(w, r)
	})
}

func withContentTypes(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ext := strings.ToLower(filepath.Ext(r.URL.Path))
		switch ext {
		case ".css":
			w.Header().Set("Content-Type", "text/css; charset=utf-8")
		case ".js":
			w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		case ".html":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
		case ".svg":
			w.Header().Set("Content-Type", "image/svg+xml")
		case ".ico":
			w.Header().Set("Content-Type", "image/x-icon")
		}
		next.ServeHTTP(w, r)
	})
}

func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}


func migrate(ctx context.Context, db *pgxpool.Pool) error {
	_, err := db.Exec(ctx, `
create table if not exists waitlist_signups (
  id bigserial primary key,
  email text not null,
  created_at timestamptz not null default now(),
  source text null,
  ip inet null,
  user_agent text null
);

create unique index if not exists waitlist_signups_email_uniq
  on waitlist_signups (lower(email));
`)
	return err
}

func (s *server) healthz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.db.Ping(ctx); err != nil {
		http.Error(w, "db not ready", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *server) waitlist(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		s.cors(w, r)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.cors(w, r)

	// Limit body to keep things cheap
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)

	var req waitlistReq
	ct := r.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "application/json") {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
	} else {
		// Accept regular form posts too
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		req.Email = r.FormValue("email")
		req.Honeypot = r.FormValue("website")
		req.Source = r.FormValue("source")
	}

	// Bot trap
	if strings.TrimSpace(req.Honeypot) != "" {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))
	if !emailRe.MatchString(email) || len(email) > 320 {
		http.Error(w, "invalid email", http.StatusBadRequest)
		return
	}

	source := strings.TrimSpace(req.Source)
	if len(source) > 120 {
		source = source[:120]
	}

	ip := clientIP(r)
	ua := r.Header.Get("User-Agent")
	if len(ua) > 400 {
		ua = ua[:400]
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	_, err := s.db.Exec(ctx, `
insert into waitlist_signups (email, source, ip, user_agent)
values ($1, $2, $3, $4)
on conflict (lower(email)) do nothing
`, email, nullIfEmpty(source), ip, nullIfEmpty(ua))
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *server) cors(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return
	}
	if s.origin != "" && origin != s.origin {
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Vary", "Origin")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
}

func clientIP(r *http.Request) any {
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			ipStr := strings.TrimSpace(parts[0])
			if ip := net.ParseIP(ipStr); ip != nil {
				return ipStr
			}
		}
	}

	xri := strings.TrimSpace(r.Header.Get("X-Real-IP"))
	if xri != "" {
		if ip := net.ParseIP(xri); ip != nil {
			return xri
		}
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return nil
	}
	if ip := net.ParseIP(host); ip == nil {
		return nil
	}
	return host
}

func nullIfEmpty(s string) any {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return s
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func getenv(key, fallback string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	return v
}
