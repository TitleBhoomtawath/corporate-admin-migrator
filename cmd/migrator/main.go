package main

import (
	"corporate-admin-migrator/app"
	"corporate-admin-migrator/app/keymaker"
	"crypto/rsa"
	"crypto/x509"
	"encoding/csv"
	"encoding/pem"
	"flag"
	"io/ioutil"
	"log"
	"os"
	"time"
)

func readPrivateKey(privateKey string) *rsa.PrivateKey {
	// decode pem file
	block, _ := pem.Decode([]byte(privateKey))

	if block == nil {
		log.Fatal("Cannot decode private key from sts_cert")
	}

	// parse private key
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Fatal("Cannot parse private key", err)
	}

	return key
}

func readCSV(reader *csv.Reader) ([]keymaker.Credential, error) {
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}

	creds := make([]keymaker.Credential, 0, len(records))
	for _, r := range records {
		cred := keymaker.Credential{
			ID:       r[0],
			Email:    r[1],
			Password: r[2],
			Salt:     r[3],
		}
		creds = append(creds, cred)
	}

	return creds, nil
}

func main() {
	var (
		dryrun   bool
		filePath string
	)

	flag.StringVar(&filePath, "f", "", "file path to read")
	flag.BoolVar(&dryrun, "d", false, "default is false")
	flag.Parse()
	if filePath == "" {
		log.Panic("file is empty")
	}
	srcFile, err := os.Open(filePath)
	if err != nil {
		log.Panic(err)
	}
	reader := csv.NewReader(srcFile)
	creds, err := readCSV(reader)
	if err != nil {
		log.Panic(err)
	}
	log.Printf("read %d", len(creds))

	rawConf, err := ioutil.ReadFile("./config/staging.yaml")
	if err != nil {
		log.Panic(err)
	}

	conf, err := app.NewConfig(rawConf)
	privateKey, err := ioutil.ReadFile(conf.STS.KeyPath)
	if err != nil {
		log.Panic(err)
	}

	key := readPrivateKey((string)(privateKey))

	if dryrun {
		os.Exit(0)
	}

	stsClient := app.NewSTSClient(app.STSOptions{
		Issuer:   conf.STS.URL,
		ClientID: conf.ClientID,
		KeyID:    conf.STS.KeyID,
		Key:      key,
		TimeOut:  10 * time.Minute,
	})

	client := keymaker.SCIMClient{
		GEID:   "FP_SG",
		Config: conf.SCIM,
	}

	file, err := os.OpenFile("output.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Panic(err)
	}

	defer file.Close()
	logger := log.New(file, "output", log.LstdFlags)

	migrator := Migrator{
		stsClient:  stsClient,
		scimClient: client,
		logger:     logger,
	}

	//creds := []keymaker.Credential{{
	//	ID:       "testtitle",
	//	Email:    "test@title.com",
	//	Password: "$2y$12$ChbwHQfqD5OhGdpApsS6rOZ1GHd/m5QATPfrlguAAdE8lWsyiUTMG",
	//	Salt:     "24f270110bee22027bcb18",
	//}}
	migrator.migrateUsers(keymaker.BulkArgs{
		BulkID:      "test",
		Credentials: creds,
	})
}

type Migrator struct {
	stsClient  app.STSClient
	scimClient keymaker.SCIMClient
	logger     *log.Logger
}

func (m Migrator) migrateUsers(args keymaker.BulkArgs) {
	accessToken, err := m.stsClient.GetAccessToken()
	resp, err := m.scimClient.MigrateUsers(accessToken, args)
	if err != nil {
		m.logger.Printf("ERROR: batch: %s, %s", args.BulkID, err.Error())
	}

	for _, r := range resp.Operations {
		m.logger.Printf("batch %s, path %s status %s", r.BulkID, r.Path, r.Status)
	}
}
