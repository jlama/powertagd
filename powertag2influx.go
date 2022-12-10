package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/influxdata/influxdb-client-go/v2"
)

const ProgName string = "powertag2influx"

func main() {
	var url string
	var token string
	var orgId string
	var bucket string

	flag.StringVar(&url, "url", "http://localhost:8086", "InfluxDB server URL")
	flag.StringVar(&token, "token", "", "InfluxDB auth token")
	flag.StringVar(&orgId, "orgId", "", "InfluxDB organization ID")
	flag.StringVar(&bucket, "bucket", "", "InfluxDB bucket")
	flag.Parse()

	if token == "" {
		fmt.Fprintf(os.Stderr, "%s: --token argument is required\n", ProgName)
		os.Exit(2)
	}
	if orgId == "" {
		fmt.Fprintf(os.Stderr, "%s: --orgId argument is required\n", ProgName)
		os.Exit(2)
	}
	if bucket == "" {
		fmt.Fprintf(os.Stderr, "%s: --bucket argument is required\n", ProgName)
		os.Exit(2)
	}

	stat, _ := os.Stdin.Stat()
	if stat.Mode()&os.ModeCharDevice != 0 {
		fmt.Fprintf(os.Stderr, "%s: no data on stdin\n", ProgName)
		fmt.Fprintf(os.Stderr, "%s expects data to be piped to stdin, i.e.:\n", ProgName)
		fmt.Fprintf(os.Stderr, "    powertagd | powertag2influx\n")
		os.Exit(2)
	}

	opts := influxdb2.DefaultOptions()
	opts.SetApplicationName(ProgName)
	opts.SetLogLevel(1) // warn
	opts.SetPrecision(time.Second)
	opts.SetFlushInterval(1000 * 30) // 30s
	opts.SetBatchSize(10)

	client := influxdb2.NewClientWithOptions(url, token, opts)
	defer client.Close()

	health, err := client.Health(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", ProgName, err)
		fmt.Fprintf(os.Stderr, "%s: failed connecting to InfluxDB server", ProgName)
		os.Exit(1)
	}

	fmt.Printf("%s: connected to %s (%s %s)\n", ProgName, url, health.Name, *health.Version)

	writeAPI := client.WriteAPI(orgId, bucket)
	defer writeAPI.Flush()

	// Get errors channel
	errorsCh := writeAPI.Errors()
	// Create go proc for reading and logging errors
	go func() {
		for err := range errorsCh {
			fmt.Fprintf(os.Stderr, "%s: influxdb write error: %s\n", ProgName, err.Error())
		}
	}()

	lnscan := bufio.NewScanner(os.Stdin)
	for lnscan.Scan() {
		line := lnscan.Text()
		writeAPI.WriteRecord(line)
	}
}
