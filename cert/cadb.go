package cert

import (
	"database/sql"
	"log/slog"
	"os"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func NewDb(url string) *sql.DB {
	slog.Debug("Initializing CA database client ...")

	db, err := sql.Open("pgx", url)
	if err != nil {
		slog.Error("Could not initiate CA database client", "error", err)
		os.Exit(1)
	}

	err = db.Ping()
	if err != nil {
		slog.Error("Failed to ping CA database", "error", err)
		os.Exit(1)
	}

	return db
}
