package main

import (
	"corporate-admin-migrator/app"
	"corporate-admin-migrator/app/keymaker"
	"crypto/rsa"
	"crypto/x509"
	"encoding/csv"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"
)

const batchSize = 100

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
		dryrun      bool
		filePath    string
		concurrency int
		configPath  string
	)

	flag.StringVar(&filePath, "f", "", "file path to read")
	flag.IntVar(&concurrency, "c", 1, "number of workers")
	flag.BoolVar(&dryrun, "d", false, "default is false")
	flag.StringVar(&configPath, "config", "", "config file location")
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
	bulks := make([]keymaker.BulkArgs, 0)
	total := len(creds)
	log.Printf("read %d", total)

	bulkID := 0
	for x := 0; x < total; {
		bulkCred := make([]keymaker.Credential, 0, batchSize)
		for i := 0; i < batchSize && x < total; i++ {
			bulkCred = append(bulkCred, creds[x])
			x++
		}
		bulks = append(bulks, keymaker.BulkArgs{
			BulkID:      fmt.Sprintf("batch-%d", bulkID),
			Credentials: bulkCred,
		})
		bulkID++
	}

	rawConf, err := ioutil.ReadFile(configPath)
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

	in := make(chan keymaker.BulkArgs)
	done := make(chan error)

	since := time.Now()

	for i := 0; i < concurrency; i++ {
		go migrator.migrateUsers(in, done)
	}

	fmt.Println("start migrating users")
	go func() {
		for i, _ := range bulks {
			in <- bulks[i]
		}
		close(in)
	}()

	for ret := range done {
		if ret != nil {
			fmt.Println(ret.Error())
			fmt.Println("Elapsed time", time.Since(since))
			break
		}
	}
}

type Migrator struct {
	stsClient  app.STSClient
	scimClient keymaker.SCIMClient
	logger     *log.Logger
}

func (m Migrator) migrateUsers(in chan keymaker.BulkArgs, doneChan chan error) {
	for args := range in {
		fmt.Printf("begin batch %s\n", args.BulkID)
		m.logger.Printf("begin batch %s\n", args.BulkID)
		accessToken, err := m.stsClient.GetAccessToken()
		resp, err := m.scimClient.MigrateUsers(accessToken, args)
		if err != nil {
			fmt.Printf("ERROR: batch: %s, %s\n", args.BulkID, err.Error())
			m.logger.Printf("ERROR: batch: %s, %s\n", args.BulkID, err.Error())
		}

		for _, r := range resp.Operations {
			fmt.Printf("batch %s, path %s status %s\n", r.BulkID, r.Path, r.Status)
			m.logger.Printf("batch %s, path %s status %s\n", r.BulkID, r.Path, r.Status)
		}
		time.Sleep(1 * time.Second)
	}
	doneChan <- fmt.Errorf("finish")
}
