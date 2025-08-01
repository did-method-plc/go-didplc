package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/bluesky-social/indigo/atproto/crypto"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/did-method-plc/go-didplc"

	"github.com/urfave/cli/v2"
)

const PLCLI_USER_AGENT = "go-didplc/plcli"

func main() {
	app := cli.App{
		Name:  "plcli",
		Usage: "simple CLI client tool for PLC operations",
	}
	app.Flags = []cli.Flag{
		&cli.StringFlag{
			Name:    "plc-host",
			Usage:   "method, hostname, and port of PLC registry",
			Value:   "https://plc.directory",
			EnvVars: []string{"PLC_HOST"},
		},
	}
	app.Commands = []*cli.Command{
		{
			Name:      "resolve",
			Usage:     "resolve a DID from remote PLC directory",
			ArgsUsage: "<did>",
			Action:    runResolve,
		},
		{
			Name:      "submit",
			Usage:     "submit a PLC operation (reads JSON from stdin)",
			ArgsUsage: "<did>",
			Action:    runSubmit,
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:    "plc-private-rotation-key",
					Usage:   "private key used as a rotation key, if operation is not signed (multibase syntax)",
					EnvVars: []string{"PLC_PRIVATE_ROTATION_KEY"},
				},
			},
		},
		{
			Name:      "oplog",
			Usage:     "fetch log of operations from PLC directory, for a single DID",
			ArgsUsage: "<did>",
			Action:    runOpLog,
		},
		{
			Name:      "auditlog",
			Usage:     "fetch audit log of operations from PLC directory, for a single DID (includes nullified ops, timestamps)",
			ArgsUsage: "<did>",
			Action:    runAuditLog,
		},
		{
			Name:      "verify",
			Usage:     "fetch audit log for a DID, and verify all operations",
			ArgsUsage: "<did>",
			Action:    runVerify,
			Flags: []cli.Flag{
				&cli.BoolFlag{
					Name:  "audit",
					Usage: "audit mode, with nullified entries included",
				},
			},
		},
		{
			Name:   "keygen",
			Usage:  "generate a fresh k256 private key, printed to stdout as a multibase string",
			Action: runKeyGen,
		},
		{
			Name:   "derive_pubkey",
			Usage:  "derive a public key and print to stdout in did:key format",
			Action: runDerivePubkey,
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:    "plc-private-rotation-key",
					Usage:   "private key used as input (multibase syntax)",
					EnvVars: []string{"PLC_PRIVATE_ROTATION_KEY"},
				},
			},
		},
	}
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})
	slog.SetDefault(slog.New(h))
	app.RunAndExitOnError()
}

func runResolve(cctx *cli.Context) error {
	ctx := context.Background()
	s := cctx.Args().First()
	if s == "" {
		fmt.Println("need to provide DID as an argument")
		os.Exit(-1)
	}

	did, err := syntax.ParseDID(s)
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}

	c := didplc.Client{
		DirectoryURL: cctx.String("plc-host"),
		UserAgent:    PLCLI_USER_AGENT,
	}
	doc, err := c.Resolve(ctx, did.String())
	if err != nil {
		return err
	}
	jsonBytes, err := json.MarshalIndent(&doc, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(jsonBytes))
	return nil
}

func runSubmit(cctx *cli.Context) error {
	ctx := context.Background()

	c := didplc.Client{
		DirectoryURL: cctx.String("plc-host"),
		UserAgent:    PLCLI_USER_AGENT,
	}

	inBytes, err := io.ReadAll(os.Stdin)
	if err != nil {
		return err
	}
	var enum didplc.OpEnum
	if err := json.Unmarshal(inBytes, &enum); err != nil {
		return err
	}
	op := enum.AsOperation()

	s := cctx.Args().First()
	var did_string string
	if s == "" {
		if !op.IsGenesis() {
			fmt.Println("a DID must be provided as argument for non-genesis ops")
			os.Exit(-1)
		}
		// else, did string will be computed after signing
	} else {
		// it's already a string, but we round-trip it to make sure it's well-formed
		parsed_did, err := syntax.ParseDID(s)
		if err != nil {
			return err
		}
		did_string = parsed_did.String()
	}

	if !op.IsSigned() {
		privStr := cctx.String("plc-private-rotation-key")
		if privStr == "" {
			return fmt.Errorf("operation is not signed and no privte key provided")
		}
		priv, err := crypto.ParsePrivateMultibase(privStr)
		if err != nil {
			return err
		}
		if err := op.Sign(priv); err != nil {
			return err
		}
	}

	// This is a genesis op, DID must be computed
	if op.IsGenesis() {
		did_string, err = op.DID()
		if err != nil {
			return err
		}
	}

	if err := c.Submit(ctx, did_string, op); err != nil {
		return err
	}

	fmt.Printf("Successfully submited operation: %s/%s\n", c.DirectoryURL, did_string)
	return nil
}

func fetchOplog(cctx *cli.Context) ([]didplc.OpEnum, error) {
	ctx := context.Background()
	s := cctx.Args().First()
	if s == "" {
		return nil, fmt.Errorf("need to provide DID as an argument")
	}

	did, err := syntax.ParseDID(s)
	if err != nil {
		return nil, err
	}

	c := didplc.Client{
		DirectoryURL: cctx.String("plc-host"),
		UserAgent:    PLCLI_USER_AGENT,
	}
	entries, err := c.OpLog(ctx, did.String())
	if err != nil {
		return nil, err
	}
	return entries, nil
}

func runOpLog(cctx *cli.Context) error {
	entries, err := fetchOplog(cctx)
	if err != nil {
		return err
	}

	jsonBytes, err := json.MarshalIndent(&entries, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(jsonBytes))
	return nil
}

func fetchAuditlog(cctx *cli.Context) ([]didplc.LogEntry, error) {
	ctx := context.Background()
	s := cctx.Args().First()
	if s == "" {
		return nil, fmt.Errorf("need to provide DID as an argument")
	}

	did, err := syntax.ParseDID(s)
	if err != nil {
		return nil, err
	}

	c := didplc.Client{
		DirectoryURL: cctx.String("plc-host"),
		UserAgent:    PLCLI_USER_AGENT,
	}
	entries, err := c.AuditLog(ctx, did.String())
	if err != nil {
		return nil, err
	}
	return entries, nil
}

func runAuditLog(cctx *cli.Context) error {
	entries, err := fetchAuditlog(cctx)
	if err != nil {
		return err
	}

	jsonBytes, err := json.MarshalIndent(&entries, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(jsonBytes))
	return nil
}

func runVerify(cctx *cli.Context) error {
	entries, err := fetchAuditlog(cctx)
	if err != nil {
		return err
	}

	err = didplc.VerifyOpLog(entries)
	if err != nil {
		return err
	}

	fmt.Println("valid")
	return nil
}

func runKeyGen(cctx *cli.Context) error {
	// TODO: support P256 also
	privkey, err := crypto.GeneratePrivateKeyK256()
	if err != nil {
		return err
	}

	fmt.Println(privkey.Multibase())

	return nil
}

func runDerivePubkey(cctx *cli.Context) error {
	privStr := cctx.String("plc-private-rotation-key")
	if privStr == "" {
		return fmt.Errorf("private key is required")
	}
	privkey, err := crypto.ParsePrivateMultibase(privStr)
	if err != nil {
		return err
	}

	pubkey, err := privkey.PublicKey()
	if err != nil {
		return err
	}

	fmt.Println(pubkey.DIDKey())

	return nil
}
