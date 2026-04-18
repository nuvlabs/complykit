package cmd

import (
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/complykit/complykit/internal/evidence"
	"github.com/complykit/complykit/internal/share"
)

//go:embed dashboard.html
var dashboardHTML embed.FS

var (
	flagServePort string
)

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

func runServe(cmd *cobra.Command, args []string) error {
	bold := color.New(color.Bold)
	cyan := color.New(color.FgCyan)

	store := evidence.NewStore("")

	mux := http.NewServeMux()

	// serve dashboard
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		data, err := dashboardHTML.ReadFile("dashboard.html")
		if err != nil {
			http.Error(w, "dashboard not found", 500)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(data)
	})

	// latest scan
	mux.HandleFunc("/api/latest", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		rec, err := store.Latest()
		if err != nil || rec == nil {
			w.Write([]byte("null"))
			return
		}
		json.NewEncoder(w).Encode(rec)
	})

	// history (list without findings to keep payload small)
	mux.HandleFunc("/api/history", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		records, err := store.List()
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

	// shared read-only view — /share/<token>
	mux.HandleFunc("/share/", func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.URL.Path, "/share/")
		recordID, err := share.Verify(token)
		if err != nil {
			http.Error(w, "Link expired or invalid.", http.StatusForbidden)
			return
		}
		// serve the dashboard with the record pre-loaded
		data, _ := dashboardHTML.ReadFile("dashboard.html")
		// inject a bootstrap script to load the specific record
		script := fmt.Sprintf(`<script>window.__SHARE_RECORD_ID = %q;</script>`, recordID)
		html := strings.Replace(string(data), "</head>", script+"</head>", 1)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(html))
	})

	// specific record by id
	mux.HandleFunc("/api/record/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		id := strings.TrimPrefix(r.URL.Path, "/api/record/")
		records, _ := store.List()
		for _, rec := range records {
			if rec.ID == id {
				json.NewEncoder(w).Encode(rec)
				return
			}
		}
		http.NotFound(w, r)
	})

	addr := ":" + flagServePort
	fmt.Println()
	bold.Println("  ComplyKit Dashboard")
	cyan.Printf("  http://localhost:%s\n\n", flagServePort)
	fmt.Printf("  Serving evidence from: %s\n", store.Dir())
	fmt.Println("  Press Ctrl+C to stop")
	fmt.Println()

	return http.ListenAndServe(addr, mux)
}
