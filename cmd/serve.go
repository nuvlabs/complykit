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

		// Seed super admin from env vars on every startup (idempotent upsert)
		if email := os.Getenv("SUPER_ADMIN_EMAIL"); email != "" {
			pass := os.Getenv("SUPER_ADMIN_PASSWORD")
			if pass == "" {
				return fmt.Errorf("SUPER_ADMIN_EMAIL is set but SUPER_ADMIN_PASSWORD is empty")
			}
			if err := database.SeedSuperAdmin(ctx, email, pass); err != nil {
				return fmt.Errorf("seed super admin: %w", err)
			}
			color.New(color.FgYellow).Printf("  Super admin: %s\n", email)
		}
	} else {
		fileStore := evidence.NewStore("")
		store = &fileStoreAdapter{s: fileStore}
		storageDesc = fmt.Sprintf("file store (%s)", fileStore.Dir())
	}

	// storeForRequest resolves the correct org store for a request.
	// Super admins may pass X-Org-ID to view any org's data.
	storeForRequest := func(r *http.Request) recordStore {
		if database == nil {
			return store
		}
		claims := auth.ClaimsFrom(r)
		orgID := claims.OrgID
		if claims.Role == "super_admin" {
			if override := r.Header.Get("X-Org-ID"); override != "" {
				orgID = override
			}
		}
		return appdb.NewOrgStore(database, orgID)
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
		s := storeForRequest(r)
		rec, err := s.Latest(r.Context())
		if err != nil || rec == nil {
			w.Write([]byte("null"))
			return
		}
		json.NewEncoder(w).Encode(rec)
	})

	protected.HandleFunc("/api/history", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		s := storeForRequest(r)
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
		out := make([]summary, 0, len(records))
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
		id := strings.TrimPrefix(r.URL.Path, "/api/record/")
		rec, err := storeForRequest(r).GetByID(r.Context(), id)
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
		id := strings.TrimPrefix(r.URL.Path, "/api/share/")
		if _, err := storeForRequest(r).GetByID(r.Context(), id); err != nil {
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
		id := strings.TrimPrefix(r.URL.Path, "/api/export/")
		format := r.URL.Query().Get("format")
		if format == "" {
			format = "json"
		}
		rec, err := storeForRequest(r).GetByID(r.Context(), id)
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

	// ── Admin routes (require admin or super_admin role) ───────────────────────

	// GET /api/admin/users — list users in the caller's org (super_admin sees all)
	protected.HandleFunc("/api/admin/users", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if database == nil {
			http.Error(w, `{"error":"requires database"}`, http.StatusServiceUnavailable)
			return
		}
		claims := auth.ClaimsFrom(r)
		if claims.Role != "admin" && claims.Role != "super_admin" {
			http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
			return
		}
		users, err := database.ListUsers(r.Context(), claims.OrgID)
		if err != nil {
			http.Error(w, `{"error":"could not list users"}`, http.StatusInternalServerError)
			return
		}
		type userResp struct {
			ID        string `json:"id"`
			Email     string `json:"email"`
			Role      string `json:"role"`
			OrgID     string `json:"org_id"`
			CreatedAt string `json:"created_at"`
		}
		var out []userResp
		for _, u := range users {
			out = append(out, userResp{
				ID:        u.ID,
				Email:     u.Email,
				Role:      u.Role,
				OrgID:     u.OrgID,
				CreatedAt: u.CreatedAt.Format("2006-01-02T15:04:05Z"),
			})
		}
		json.NewEncoder(w).Encode(out)
	})

	// POST /api/admin/reset-password {"email":"...", "password":"..."}
	protected.HandleFunc("/api/admin/reset-password", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		if database == nil {
			http.Error(w, `{"error":"requires database"}`, http.StatusServiceUnavailable)
			return
		}
		claims := auth.ClaimsFrom(r)
		if claims.Role != "admin" && claims.Role != "super_admin" {
			http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
			return
		}
		var body struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Email == "" || body.Password == "" {
			http.Error(w, `{"error":"email and password are required"}`, http.StatusBadRequest)
			return
		}
		if err := database.ResetPassword(r.Context(), claims.OrgID, body.Email, body.Password); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	// GET /api/admin/orgs — list all orgs (super_admin only)
	protected.HandleFunc("/api/admin/orgs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if database == nil {
			http.Error(w, `{"error":"requires database"}`, http.StatusServiceUnavailable)
			return
		}
		claims := auth.ClaimsFrom(r)

		if r.Method == http.MethodGet {
			if claims.Role != "super_admin" {
				http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
				return
			}
			orgs, err := database.ListOrgs(r.Context())
			if err != nil {
				http.Error(w, `{"error":"could not list orgs"}`, http.StatusInternalServerError)
				return
			}
			type orgResp struct {
				ID        string `json:"id"`
				Slug      string `json:"slug"`
				Name      string `json:"name"`
				Plan      string `json:"plan"`
				CreatedAt string `json:"created_at"`
			}
			var out []orgResp
			for _, o := range orgs {
				out = append(out, orgResp{o.ID, o.Slug, o.Name, o.Plan, o.CreatedAt.Format("2006-01-02T15:04:05Z")})
			}
			json.NewEncoder(w).Encode(out)
			return
		}

		// POST — create org + initial admin user (super_admin only)
		if r.Method == http.MethodPost {
			if claims.Role != "super_admin" {
				http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
				return
			}
			var body struct {
				Slug          string `json:"slug"`
				Name          string `json:"name"`
				AdminEmail    string `json:"admin_email"`
				AdminPassword string `json:"admin_password"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
				return
			}
			if body.Slug == "" || body.Name == "" || body.AdminEmail == "" || body.AdminPassword == "" {
				http.Error(w, `{"error":"slug, name, admin_email and admin_password are required"}`, http.StatusBadRequest)
				return
			}
			org, err := database.CreateOrgWithAdmin(r.Context(), body.Slug, body.Name, body.AdminEmail, body.AdminPassword)
			if err != nil {
				http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{
				"id": org.ID, "slug": org.Slug, "name": org.Name,
				"admin_email": body.AdminEmail,
			})
			return
		}

		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
	})

	// POST /api/admin/create-user — create user in an org
	// admin: creates in their own org only
	// super_admin: can specify any org_id
	protected.HandleFunc("/api/admin/create-user", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		if database == nil {
			http.Error(w, `{"error":"requires database"}`, http.StatusServiceUnavailable)
			return
		}
		claims := auth.ClaimsFrom(r)
		if claims.Role != "admin" && claims.Role != "super_admin" {
			http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
			return
		}
		var body struct {
			Email    string `json:"email"`
			Password string `json:"password"`
			Role     string `json:"role"`
			OrgID    string `json:"org_id"` // only honoured for super_admin
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Email == "" || body.Password == "" {
			http.Error(w, `{"error":"email and password are required"}`, http.StatusBadRequest)
			return
		}
		if body.Role == "" {
			body.Role = "member"
		}
		// non-super-admins cannot create super_admins or admins in other orgs
		targetOrgID := claims.OrgID
		if claims.Role == "super_admin" && body.OrgID != "" {
			targetOrgID = body.OrgID
		}
		if claims.Role != "super_admin" && body.Role == "super_admin" {
			http.Error(w, `{"error":"cannot assign super_admin role"}`, http.StatusForbidden)
			return
		}
		user, err := database.CreateUser(r.Context(), targetOrgID, body.Email, body.Password, body.Role)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{
			"id": user.ID, "email": user.Email, "role": user.Role, "org_id": user.OrgID,
		})
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
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key, X-Org-ID")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		if r.Method == http.MethodOptions {
			return
		}
		next.ServeHTTP(w, r)
	})
}
