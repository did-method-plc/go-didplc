package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/did-method-plc/go-didplc"

	"github.com/urfave/cli/v3"
)

const PLCLI_USER_AGENT = "go-didplc/plcli"

func main() {
	app := cli.Command{
		Name:  "plcli",
		Usage: "simple CLI client tool for PLC operations",
	}
	app.Flags = []cli.Flag{
		&cli.StringFlag{
			Name:    "plc-host",
			Usage:   "method, hostname, and port of PLC registry",
			Value:   "https://plc.directory",
			Sources: cli.EnvVars("PLC_HOST"),
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
					Sources: cli.EnvVars("PLC_PRIVATE_ROTATION_KEY"),
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
			Usage:  "generate a fresh private key, printed to stdout as a multibase string",
			Action: runKeyGen,
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "type",
					Usage: "key type; one of 'K-256' or 'P-256'",
					Value: "K-256",
				},
			},
		},
		{
			Name:   "derive_pubkey",
			Usage:  "derive a public key and print to stdout in did:key format",
			Action: runDerivePubkey,
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:    "plc-private-rotation-key",
					Usage:   "private key used as input (multibase syntax)",
					Sources: cli.EnvVars("PLC_PRIVATE_ROTATION_KEY"),
				},
			},
		},
	}
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})
	slog.SetDefault(slog.New(h))
	if err := app.Run(context.Background(), os.Args); err != nil {
		fmt.Println("Error:", err)
		os.Exit(-1)
	}
}

func runResolve(ctx context.Context, cmd *cli.Command) error {
	s := cmd.Args().First()
	if s == "" {
		return fmt.Errorf("need to provide DID as an argument")
	}

	did, err := syntax.ParseDID(s)
	if err != nil {
		return err
	}

	c := didplc.Client{
		DirectoryURL: cmd.String("plc-host"),
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

func runSubmit(ctx context.Context, cmd *cli.Command) error {

	c := didplc.Client{
		DirectoryURL: cmd.String("plc-host"),
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

	s := cmd.Args().First()
	var did_string string
	if s == "" {
		if !op.IsGenesis() {
			return fmt.Errorf("a DID must be provided as argument for non-genesis ops")
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
		privStr := cmd.String("plc-private-rotation-key")
		if privStr == "" {
			return fmt.Errorf("operation is not signed and no privte key provided")
		}
		priv, err := atcrypto.ParsePrivateMultibase(privStr)
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

func fetchOplog(ctx context.Context, cmd *cli.Command) ([]didplc.OpEnum, error) {
	s := cmd.Args().First()
	if s == "" {
		return nil, fmt.Errorf("need to provide DID as an argument")
	}

	did, err := syntax.ParseDID(s)
	if err != nil {
		return nil, err
	}

	c := didplc.Client{
		DirectoryURL: cmd.String("plc-host"),
		UserAgent:    PLCLI_USER_AGENT,
	}
	entries, err := c.OpLog(ctx, did.String())
	if err != nil {
		return nil, err
	}
	return entries, nil
}

func runOpLog(ctx context.Context, cmd *cli.Command) error {
	entries, err := fetchOplog(ctx, cmd)
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

func fetchAuditlog(ctx context.Context, cmd *cli.Command) ([]didplc.LogEntry, error) {
	s := cmd.Args().First()
	if s == "" {
		return nil, fmt.Errorf("need to provide DID as an argument")
	}

	did, err := syntax.ParseDID(s)
	if err != nil {
		return nil, err
	}

	c := didplc.Client{
		DirectoryURL: cmd.String("plc-host"),
		UserAgent:    PLCLI_USER_AGENT,
	}
	entries, err := c.AuditLog(ctx, did.String())
	if err != nil {
		return nil, err
	}
	return entries, nil
}

func runAuditLog(ctx context.Context, cmd *cli.Command) error {
	entries, err := fetchAuditlog(ctx, cmd)
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

func runVerify(ctx context.Context, cmd *cli.Command) error {
	entries, err := fetchAuditlog(ctx, cmd)
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

func runKeyGen(ctx context.Context, cmd *cli.Command) error {
	t := cmd.String("type")
	switch t {
	case "K-256", "K256", "k256":
		privkey, err := atcrypto.GeneratePrivateKeyK256()
		if err != nil {
			return err
		}
		fmt.Println(privkey.Multibase())
	case "P-256", "P256", "p256":
		privkey, err := atcrypto.GeneratePrivateKeyP256()
		if err != nil {
			return err
		}
		fmt.Println(privkey.Multibase())
	default:
		return fmt.Errorf("unknown key type: %s", t)
	}
	return nil
}

func runDerivePubkey(ctx context.Context, cmd *cli.Command) error {
	privStr := cmd.String("plc-private-rotation-key")
	if privStr == "" {
		return fmt.Errorf("private key is required")
	}
	privkey, err := atcrypto.ParsePrivateMultibase(privStr)
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
