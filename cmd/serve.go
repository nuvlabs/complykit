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

func (a *fileStoreAdapter) Latest(_ context.Context) (*evidence.Record, error) {
	return a.s.Latest()
}
func (a *fileStoreAdapter) List(_ context.Context) ([]evidence.Record, error) {
	return a.s.List()
}
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

	var store recordStore
	storageDesc := "file store"

	if dsn := os.Getenv("DATABASE_URL"); dsn != "" {
		database, err := appdb.Connect(ctx, dsn)
		if err != nil {
			return fmt.Errorf("connect to database: %w", err)
		}
		defer database.Close()

		slug := os.Getenv("ORG_SLUG")
		if slug == "" {
			slug = "default"
		}
		name := os.Getenv("ORG_NAME")
		if name == "" {
			name = slug
		}
		org, err := database.GetOrCreateOrg(ctx, slug, name)
		if err != nil {
			return fmt.Errorf("get or create org: %w", err)
		}
		store = appdb.NewOrgStore(database, org.ID)
		storageDesc = fmt.Sprintf("postgres (org: %s)", org.Slug)
	} else {
		fileStore := evidence.NewStore("")
		store = &fileStoreAdapter{s: fileStore}
		storageDesc = fmt.Sprintf("file store (%s)", fileStore.Dir())
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		data, err := dashboardHTML.ReadFile("dashboard.html")
		if err != nil {
			http.Error(w, "dashboard not found", 500)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(data)
	})

	mux.HandleFunc("/api/latest", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		rec, err := store.Latest(r.Context())
		if err != nil || rec == nil {
			w.Write([]byte("null"))
			return
		}
		json.NewEncoder(w).Encode(rec)
	})

	mux.HandleFunc("/api/history", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		records, err := store.List(r.Context())
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
		var summaries []summary
		for _, rec := range records {
			summaries = append(summaries, summary{
				ID:          rec.ID,
				CollectedAt: rec.CollectedAt.Format("2006-01-02T15:04:05Z"),
				Framework:   rec.Framework,
				Score:       rec.Score,
				Passed:      rec.Passed,
				Failed:      rec.Failed,
				Skipped:     rec.Skipped,
			})
		}
		json.NewEncoder(w).Encode(summaries)
	})

	mux.HandleFunc("/api/record/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		id := strings.TrimPrefix(r.URL.Path, "/api/record/")
		rec, err := store.GetByID(r.Context(), id)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(rec)
	})

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

	mux.HandleFunc("/api/share/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/api/share/")
		if id == "" {
			http.Error(w, "missing record id", http.StatusBadRequest)
			return
		}
		if _, err := store.GetByID(r.Context(), id); err != nil {
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

	mux.HandleFunc("/api/export/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/api/export/")
		format := r.URL.Query().Get("format")
		if format == "" {
			format = "json"
		}
		rec, err := store.GetByID(r.Context(), id)
		if err != nil {
			http.NotFound(w, r)
			return
		}

		result := &engine.ScanResult{
			Findings: rec.Findings,
			Passed:   rec.Passed,
			Failed:   rec.Failed,
			Skipped:  rec.Skipped,
			Score:    rec.Score,
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
			writer := csv.NewWriter(w)
			writer.Write([]string{"Check ID", "Title", "Status", "Severity", "Integration", "Resource", "Controls", "Remediation", "Detail"})
			for _, f := range rec.Findings {
				var controls []string
				for _, c := range f.Controls {
					controls = append(controls, fmt.Sprintf("%s/%s", c.Framework, c.ID))
				}
				writer.Write([]string{
					f.CheckID, f.Title, string(f.Status), string(f.Severity),
					f.Integration, f.Resource, strings.Join(controls, " · "),
					f.Remediation, f.Detail,
				})
			}
			writer.Flush()

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
			data, err := os.ReadFile(tmp.Name())
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			w.Header().Set("Content-Type", "application/pdf")
			w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.pdf"`, filepath.Base(filenameBase)+".pdf"))
			w.Write(data)

		default:
			http.Error(w, "unknown format (use json, csv, or pdf)", http.StatusBadRequest)
		}
	})

	fmt.Println()
	bold.Println("  ComplyKit Dashboard")
	cyan.Printf("  http://localhost:%s\n\n", flagServePort)
	fmt.Printf("  Storage: %s\n", storageDesc)
	fmt.Println("  Press Ctrl+C to stop")
	fmt.Println()

	return http.ListenAndServe(":"+flagServePort, mux)
}
