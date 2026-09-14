// bit-evidence-injector creates a real, CometBFT-verifiable duplicate vote
// using one validator key from an ephemeral integration network. It is test
// infrastructure only and must never be pointed at production key material.
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/cometbft/cometbft/crypto/tmhash"
	cmtjson "github.com/cometbft/cometbft/libs/json"
	"github.com/cometbft/cometbft/privval"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	rpchttp "github.com/cometbft/cometbft/rpc/client/http"
	"github.com/cometbft/cometbft/types"
)

type result struct {
	CometEvidenceHash   string `json:"comet_evidence_hash"`
	ValidatorAddress    string `json:"validator_address"`
	ValidatorPower      int64  `json:"validator_power"`
	InfractionHeight    int64  `json:"infraction_height"`
	InfractionTimeSecs  int64  `json:"infraction_time_seconds"`
	InfractionTimeNanos int32  `json:"infraction_time_nanos"`
	TotalVotingPower    int64  `json:"total_voting_power"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	var rpcURL string
	var genesisPath string
	var privateValidatorKeyPath string
	var height int64
	flag.StringVar(&rpcURL, "rpc", "", "CometBFT RPC URL")
	flag.StringVar(&genesisPath, "genesis", "", "genesis.json path")
	flag.StringVar(&privateValidatorKeyPath, "priv-validator-key", "", "ephemeral priv_validator_key.json path")
	flag.Int64Var(&height, "height", 0, "committed infraction height")
	flag.Parse()
	if flag.NArg() != 0 || rpcURL == "" || genesisPath == "" || privateValidatorKeyPath == "" || height <= 0 {
		return errors.New("rpc, genesis, priv-validator-key, and positive height are required")
	}

	genesisBytes, err := os.ReadFile(genesisPath)
	if err != nil {
		return fmt.Errorf("read genesis: %w", err)
	}
	var genesis struct {
		ChainID string `json:"chain_id"`
	}
	if err := json.Unmarshal(genesisBytes, &genesis); err != nil {
		return fmt.Errorf("decode genesis: %w", err)
	}
	if genesis.ChainID == "" {
		return errors.New("genesis chain_id is empty")
	}
	if !strings.HasPrefix(genesis.ChainID, "bit-app-probe-") {
		return errors.New("refusing to use a private key outside a bit-app-probe integration chain")
	}

	keyBytes, err := os.ReadFile(privateValidatorKeyPath)
	if err != nil {
		return fmt.Errorf("read private validator key: %w", err)
	}
	var key privval.FilePVKey
	if err := cmtjson.Unmarshal(keyBytes, &key); err != nil {
		return fmt.Errorf("decode private validator key: %w", err)
	}
	if key.PrivKey == nil {
		return errors.New("private validator key has no private key")
	}
	publicKey := key.PrivKey.PubKey()

	client, err := rpchttp.New(rpcURL, "/websocket")
	if err != nil {
		return fmt.Errorf("create RPC client: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	block, err := client.Block(ctx, &height)
	if err != nil {
		return fmt.Errorf("load block at height %d: %w", height, err)
	}
	page, perPage := 1, 100
	validators, err := client.Validators(ctx, &height, &page, &perPage)
	if err != nil {
		return fmt.Errorf("load validators at height %d: %w", height, err)
	}
	validatorSet, err := types.ValidatorSetFromExistingValidators(validators.Validators)
	if err != nil {
		return fmt.Errorf("construct validator set: %w", err)
	}
	validatorIndex, validator := validatorSet.GetByAddress(publicKey.Address())
	if validatorIndex < 0 || validator == nil {
		return fmt.Errorf("private key address %X is absent at height %d", publicKey.Address(), height)
	}

	mock := types.NewMockPVWithParams(key.PrivKey, false, false)
	voteA, err := types.MakeVote(
		mock,
		genesis.ChainID,
		validatorIndex,
		height,
		0,
		cmtproto.PrevoteType,
		deterministicBlockID("A", height),
		block.Block.Time,
	)
	if err != nil {
		return fmt.Errorf("sign first conflicting vote: %w", err)
	}
	voteB, err := types.MakeVote(
		mock,
		genesis.ChainID,
		validatorIndex,
		height,
		0,
		cmtproto.PrevoteType,
		deterministicBlockID("B", height),
		block.Block.Time,
	)
	if err != nil {
		return fmt.Errorf("sign second conflicting vote: %w", err)
	}
	evidence, err := types.NewDuplicateVoteEvidence(voteA, voteB, block.Block.Time, validatorSet)
	if err != nil {
		return fmt.Errorf("construct duplicate vote evidence: %w", err)
	}
	broadcast, err := client.BroadcastEvidence(ctx, evidence)
	if err != nil {
		return fmt.Errorf("broadcast duplicate vote evidence: %w", err)
	}
	if !bytes.Equal(broadcast.Hash, evidence.Hash()) {
		return errors.New("RPC returned a different evidence hash")
	}

	encoded, err := json.Marshal(result{
		CometEvidenceHash:   hex.EncodeToString(evidence.Hash()),
		ValidatorAddress:    hex.EncodeToString(publicKey.Address()),
		ValidatorPower:      evidence.ValidatorPower,
		InfractionHeight:    height,
		InfractionTimeSecs:  block.Block.Time.Unix(),
		InfractionTimeNanos: int32(block.Block.Time.Nanosecond()),
		TotalVotingPower:    evidence.TotalVotingPower,
	})
	if err != nil {
		return fmt.Errorf("encode result: %w", err)
	}
	fmt.Println(string(encoded))
	return nil
}

func deterministicBlockID(label string, height int64) types.BlockID {
	return types.BlockID{
		Hash: tmhash.Sum([]byte(fmt.Sprintf("BIT-EVIDENCE-%s-BLOCK-%d", label, height))),
		PartSetHeader: types.PartSetHeader{
			Total: 1,
			Hash:  tmhash.Sum([]byte(fmt.Sprintf("BIT-EVIDENCE-%s-PARTS-%d", label, height))),
		},
	}
}
