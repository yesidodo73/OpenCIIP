package network

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/yesidodo73/OpenCIIP/internal/checks/support"
	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/executor"
	"github.com/yesidodo73/OpenCIIP/internal/model"
)

type nftInspection struct {
	tableCount              int
	chainCount              int
	ruleCount               int
	inputBaseChainCount     int
	inputDefaultDropCount   int
	inputDefaultAcceptCount int
	dynamicObjectCount      int
}

func inspectNFTRuleset(ctx context.Context, environment evaluator.Environment) (nftInspection, model.Evidence, error) {
	spec := executor.Spec{
		Name:      "nft",
		Arguments: []string{"-j", "list", "ruleset"},
		Timeout:   30 * time.Second,
		MaxOutput: 8 << 20,
	}
	result, err := environment.Commands.Run(ctx, spec)
	if err != nil {
		return nftInspection{}, model.Evidence{}, fmt.Errorf("run nft ruleset collection: %w", err)
	}
	if result.ExitCode != 0 || result.Truncated {
		return nftInspection{}, model.Evidence{}, fmt.Errorf("nft ruleset collection failed: exit=%d truncated=%t", result.ExitCode, result.Truncated)
	}
	inspection, err := parseNFTRuleset(result.Stdout)
	if err != nil {
		return nftInspection{}, model.Evidence{}, fmt.Errorf("parse nft ruleset: %w", err)
	}
	facts := map[string]any{
		"ruleset_sha256":                   hashBytes(result.Stdout),
		"table_count":                      inspection.tableCount,
		"chain_count":                      inspection.chainCount,
		"rule_count":                       inspection.ruleCount,
		"input_base_chain_count":           inspection.inputBaseChainCount,
		"input_default_drop_chain_count":   inspection.inputDefaultDropCount,
		"input_default_accept_chain_count": inspection.inputDefaultAcceptCount,
		"dynamic_object_count":             inspection.dynamicObjectCount,
	}
	addPrivateCommandFacts(facts, result)
	return inspection, support.FactEvidence("nftables-ruleset-summary", facts), nil
}

func parseNFTRuleset(data []byte) (nftInspection, error) {
	var document struct {
		NFTables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		return nftInspection{}, err
	}
	if document.NFTables == nil {
		return nftInspection{}, fmt.Errorf("nftables document is missing")
	}

	inspection := nftInspection{}
	for index, object := range document.NFTables {
		if len(object) != 1 {
			return nftInspection{}, fmt.Errorf("nftables object %d has an invalid shape", index+1)
		}
		for objectType, payload := range object {
			switch objectType {
			case "metainfo":
			case "table":
				inspection.tableCount++
			case "chain":
				inspection.chainCount++
				var chain struct {
					Hook   string `json:"hook"`
					Policy string `json:"policy"`
				}
				if err := json.Unmarshal(payload, &chain); err != nil {
					return nftInspection{}, fmt.Errorf("decode nftables chain %d: %w", index+1, err)
				}
				if strings.EqualFold(strings.TrimSpace(chain.Hook), "input") {
					inspection.inputBaseChainCount++
					switch strings.ToLower(strings.TrimSpace(chain.Policy)) {
					case "drop":
						inspection.inputDefaultDropCount++
					case "accept":
						inspection.inputDefaultAcceptCount++
					}
				}
			case "rule":
				inspection.ruleCount++
			default:
				inspection.dynamicObjectCount++
			}
		}
	}
	return inspection, nil
}

func hashBytes(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}
