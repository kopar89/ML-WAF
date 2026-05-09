package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"syscall"

	"waf/internal/config"
	"waf/internal/core"
	"waf/internal/engine"

	"go.uber.org/zap"
)

var version = "dev"

func main() {
	configPath := flag.String("config", "configs/config.yaml", "Path to config file")
	showVersion := flag.Bool("version", false, "Show version info")
	flag.Parse()

	if *showVersion {
		fmt.Printf("WAF version %s\n", version)
		os.Exit(0)
	}

	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("failed to initialize logger: %v", err)
	}
	defer logger.Sync()

	logger.Info("starting WAF", zap.String("version", version))

	cfg, err := config.LoadFromFile(*configPath)
	if err != nil {
		logger.Warn("cannot load config, using defaults", zap.String("path", *configPath), zap.Error(err))
		cfg = config.DefaultConfig()
	}

	secEngine, err := engine.NewSecurityEngine(cfg.Security.RulesFile, logger)
	if err != nil {
		logger.Warn("cannot initialize security engine, running without rules", zap.Error(err))
	}

	wafCore, err := core.New(cfg, logger, secEngine)
	if err != nil {
		logger.Fatal("failed to initialize WAF core", zap.Error(err))
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		logger.Info("received signal, shutting down", zap.String("signal", sig.String()))
		if err := wafCore.Stop(); err != nil {
			logger.Error("shutdown error", zap.Error(err))
		}
	}()

	go func() {
		logger.Info("pprof server on :6060")
		log.Println(http.ListenAndServe(":6060", nil))
	}()

	fmt.Printf("WAFCore starting on %s...\n", cfg.ListenAddr)
	logger.Info("WAFCore initialized",
		zap.String("listen_addr", cfg.ListenAddr),
		zap.String("backend_url", cfg.BackendURL),
		zap.String("rules_file", cfg.Security.RulesFile),
	)

	if err := wafCore.Start(); err != nil && err != http.ErrServerClosed {
		logger.Fatal("WAFCore failed", zap.Error(err))
	}
}
