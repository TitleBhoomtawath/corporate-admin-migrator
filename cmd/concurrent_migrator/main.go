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
	"sync"
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
		wg          sync.WaitGroup
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
	wg.Add(concurrency)
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
	d := time.Now()
	bulkPrefix := fmt.Sprintf("%d-%d-%d-", d.Year(), d.Month(), d.Day())
	for x := 0; x < total; {
		bulkCred := make([]keymaker.Credential, 0, batchSize)
		for i := 0; i < batchSize && x < total; i++ {
			bulkCred = append(bulkCred, creds[x])
			x++
		}
		bulks = append(bulks, keymaker.BulkArgs{
			BulkID:      fmt.Sprintf("%s-%d", bulkPrefix, bulkID),
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

	since := time.Now()
	logFileName := "./logs/" + since.Format(time.RFC3339) + ".log"
	file, err := os.OpenFile(logFileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
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

	for i := 0; i < concurrency; i++ {
		go migrator.migrateUsers(in, &wg)
	}

	fmt.Println("start migrating users")
	go func() {
		for i := range bulks {
			in <- bulks[i]
		}
		close(in)
	}()

	wg.Wait()
	elapsed := time.Since(since)
	fmt.Println("Elapsed time", elapsed)
	logger.Printf("Elapsed time %d", elapsed)
}

type Migrator struct {
	stsClient  app.STSClient
	scimClient keymaker.SCIMClient
	logger     *log.Logger
}

func (m Migrator) migrateUsers(in chan keymaker.BulkArgs, wg *sync.WaitGroup) {
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
		fmt.Printf("done batch %s\n", args.BulkID)
		m.logger.Printf("done batch %s\n", args.BulkID)
		time.Sleep(1 * time.Second)
	}
	wg.Done()
}
