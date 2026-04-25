package cmd

import (
	"context"
	"embed"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/complykit/complykit/internal/auth"
	appdb "github.com/complykit/complykit/internal/db"
	"github.com/complykit/complykit/internal/engine"
	"github.com/complykit/complykit/internal/evidence"
	"github.com/complykit/complykit/internal/report"
	"github.com/complykit/complykit/internal/share"
)

//go:embed dashboard.html
var dashboardHTML embed.FS

var flagServePort string

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the compliance dashboard web UI",
	Example: `  comply serve
  comply serve --port 9000`,
	RunE: runServe,
}

func init() {
	serveCmd.Flags().StringVar(&flagServePort, "port", "8080", "Port to listen on")
	rootCmd.AddCommand(serveCmd)
}

// recordStore abstracts file-based and Postgres-based evidence storage.
type recordStore interface {
	Latest(ctx context.Context) (*evidence.Record, error)
	List(ctx context.Context) ([]evidence.Record, error)
	GetByID(ctx context.Context, id string) (*evidence.Record, error)
}

// fileStoreAdapter wraps evidence.Store to satisfy recordStore.
type fileStoreAdapter struct{ s *evidence.Store }

func (a *fileStoreAdapter) Latest(_ context.Context) (*evidence.Record, error) { return a.s.Latest() }
func (a *fileStoreAdapter) List(_ context.Context) ([]evidence.Record, error)  { return a.s.List() }
func (a *fileStoreAdapter) GetByID(_ context.Context, id string) (*evidence.Record, error) {
	records, err := a.s.List()
	if err != nil {
		return nil, err
	}
	for i := range records {
		if records[i].ID == id {
			return &records[i], nil
		}
	}
	return nil, fmt.Errorf("record not found: %s", id)
}

func runServe(cmd *cobra.Command, args []string) error {
	bold := color.New(color.Bold)
	cyan := color.New(color.FgCyan)
	ctx := context.Background()

	var (
		store       recordStore
		database    *appdb.DB
		storageDesc string
	)

	if dsn := os.Getenv("DATABASE_URL"); dsn != "" {
		var err error
		database, err = appdb.Connect(ctx, dsn)
		if err != nil {
			return fmt.Errorf("connect to database: %w", err)
		}
		defer database.Close()
		storageDesc = "postgres"
	} else {
		fileStore := evidence.NewStore("")
		store = &fileStoreAdapter{s: fileStore}
		storageDesc = fmt.Sprintf("file store (%s)", fileStore.Dir())
	}

	// storeForOrg returns a recordStore scoped to the given orgID (Postgres only).
	storeForOrg := func(orgID string) recordStore {
		if database != nil {
			return appdb.NewOrgStore(database, orgID)
		}
		return store
	}

	mux := http.NewServeMux()

	// ── Public routes ──────────────────────────────────────────────────────────

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		data, err := dashboardHTML.ReadFile("dashboard.html")
		if err != nil {
			http.Error(w, "dashboard not found", 500)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(data)
	})

	// POST /api/auth/login  {"email":"...", "password":"..."}
	mux.HandleFunc("/api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			w.Header().Set("Access-Control-Allow-Methods", "POST")
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		if database == nil {
			http.Error(w, `{"error":"auth requires DATABASE_URL"}`, http.StatusServiceUnavailable)
			return
		}
		var body struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
			return
		}
		user, err := database.AuthenticateUser(r.Context(), body.Email, body.Password)
		if err != nil {
			http.Error(w, `{"error":"invalid credentials"}`, http.StatusUnauthorized)
			return
		}
		token, err := auth.IssueToken(user.ID, user.OrgID, user.Email, user.Role)
		if err != nil {
			http.Error(w, `{"error":"could not issue token"}`, http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{
			"token":  token,
			"org_id": user.OrgID,
			"email":  user.Email,
			"role":   user.Role,
		})
	})

	// POST /api/push  — CLI pushes scan results using an API key
	mux.HandleFunc("/api/push", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		if database == nil {
			http.Error(w, `{"error":"push requires DATABASE_URL"}`, http.StatusServiceUnavailable)
			return
		}
		rawKey := r.Header.Get("X-API-Key")
		if rawKey == "" {
			http.Error(w, `{"error":"missing X-API-Key header"}`, http.StatusUnauthorized)
			return
		}
		org, err := database.ResolveAPIKey(r.Context(), rawKey)
		if err != nil {
			http.Error(w, `{"error":"invalid api key"}`, http.StatusUnauthorized)
			return
		}
		var body struct {
			Framework string          `json:"framework"`
			Score     int             `json:"score"`
			Passed    int             `json:"passed"`
			Failed    int             `json:"failed"`
			Skipped   int             `json:"skipped"`
			Findings  []engine.Finding `json:"findings"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, `{"error":"invalid body"}`, http.StatusBadRequest)
			return
		}
		result := &engine.ScanResult{
			Findings: body.Findings,
			Passed:   body.Passed,
			Failed:   body.Failed,
			Skipped:  body.Skipped,
			Score:    body.Score,
		}
		orgStore := appdb.NewOrgStore(database, org.ID)
		id, err := orgStore.Save(r.Context(), result, body.Framework)
		if err != nil {
			http.Error(w, `{"error":"failed to save scan"}`, http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"id": id, "org": org.Slug})
	})

	// Share view — public but token-gated
	mux.HandleFunc("/share/", func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.URL.Path, "/share/")
		recordID, err := share.Verify(token)
		if err != nil {
			http.Error(w, "Link expired or invalid.", http.StatusForbidden)
			return
		}
		data, _ := dashboardHTML.ReadFile("dashboard.html")
		script := fmt.Sprintf(`<script>window.__SHARE_RECORD_ID = %q;</script>`, recordID)
		html := strings.Replace(string(data), "</head>", script+"</head>", 1)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(html))
	})

	// ── Protected routes (JWT required) ────────────────────────────────────────

	protected := http.NewServeMux()

	protected.HandleFunc("/api/latest", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		claims := auth.ClaimsFrom(r)
		s := storeForOrg(claims.OrgID)
		rec, err := s.Latest(r.Context())
		if err != nil || rec == nil {
			w.Write([]byte("null"))
			return
		}
		json.NewEncoder(w).Encode(rec)
	})

	protected.HandleFunc("/api/history", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		claims := auth.ClaimsFrom(r)
		s := storeForOrg(claims.OrgID)
		records, err := s.List(r.Context())
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		type summary struct {
			ID          string `json:"id"`
			CollectedAt string `json:"collected_at"`
			Framework   string `json:"framework"`
			Score       int    `json:"score"`
			Passed      int    `json:"passed"`
			Failed      int    `json:"failed"`
			Skipped     int    `json:"skipped"`
		}
		var out []summary
		for _, rec := range records {
			out = append(out, summary{
				ID:          rec.ID,
				CollectedAt: rec.CollectedAt.Format("2006-01-02T15:04:05Z"),
				Framework:   rec.Framework,
				Score:       rec.Score,
				Passed:      rec.Passed,
				Failed:      rec.Failed,
				Skipped:     rec.Skipped,
			})
		}
		json.NewEncoder(w).Encode(out)
	})

	protected.HandleFunc("/api/record/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		claims := auth.ClaimsFrom(r)
		id := strings.TrimPrefix(r.URL.Path, "/api/record/")
		rec, err := storeForOrg(claims.OrgID).GetByID(r.Context(), id)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(rec)
	})

	protected.HandleFunc("/api/share/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		claims := auth.ClaimsFrom(r)
		id := strings.TrimPrefix(r.URL.Path, "/api/share/")
		if _, err := storeForOrg(claims.OrgID).GetByID(r.Context(), id); err != nil {
			http.NotFound(w, r)
			return
		}
		link, err := share.Create(id, "dashboard-share", share.DefaultTTL)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{
			"token":      link.Token,
			"url":        "/share/" + link.Token,
			"expires_at": link.ExpiresAt.Format("2006-01-02T15:04:05Z"),
		})
	})

	protected.HandleFunc("/api/export/", func(w http.ResponseWriter, r *http.Request) {
		claims := auth.ClaimsFrom(r)
		id := strings.TrimPrefix(r.URL.Path, "/api/export/")
		format := r.URL.Query().Get("format")
		if format == "" {
			format = "json"
		}
		rec, err := storeForOrg(claims.OrgID).GetByID(r.Context(), id)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		result := &engine.ScanResult{
			Findings: rec.Findings, Passed: rec.Passed,
			Failed: rec.Failed, Skipped: rec.Skipped, Score: rec.Score,
		}
		filenameBase := "complykit-" + rec.Framework + "-" + rec.ID
		switch format {
		case "json":
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.json"`, filenameBase))
			json.NewEncoder(w).Encode(rec)
		case "csv":
			w.Header().Set("Content-Type", "text/csv")
			w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.csv"`, filenameBase))
			wr := csv.NewWriter(w)
			wr.Write([]string{"Check ID", "Title", "Status", "Severity", "Integration", "Resource", "Controls", "Remediation", "Detail"})
			for _, f := range rec.Findings {
				var controls []string
				for _, c := range f.Controls {
					controls = append(controls, fmt.Sprintf("%s/%s", c.Framework, c.ID))
				}
				wr.Write([]string{f.CheckID, f.Title, string(f.Status), string(f.Severity),
					f.Integration, f.Resource, strings.Join(controls, " · "), f.Remediation, f.Detail})
			}
			wr.Flush()
		case "pdf":
			tmp, err := os.CreateTemp("", filenameBase+"-*.pdf")
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			tmp.Close()
			defer os.Remove(tmp.Name())
			if err := report.WritePDF(result, rec.Framework, tmp.Name()); err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			data, _ := os.ReadFile(tmp.Name())
			w.Header().Set("Content-Type", "application/pdf")
			w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.pdf"`, filepath.Base(filenameBase)+".pdf"))
			w.Write(data)
		default:
			http.Error(w, "unknown format", http.StatusBadRequest)
		}
	})

	// Mount protected routes behind JWT middleware
	mux.Handle("/api/", corsMiddleware(auth.Require(protected)))

	fmt.Println()
	bold.Println("  ComplyKit Dashboard")
	cyan.Printf("  http://localhost:%s\n\n", flagServePort)
	fmt.Printf("  Storage: %s\n", storageDesc)
	fmt.Println("  Press Ctrl+C to stop")
	fmt.Println()

	return http.ListenAndServe(":"+flagServePort, mux)
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		if r.Method == http.MethodOptions {
			return
		}
		next.ServeHTTP(w, r)
	})
}
