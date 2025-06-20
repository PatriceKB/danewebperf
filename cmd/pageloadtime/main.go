package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yagikota/danewebperf/cmd/pageloadtime/har"
	"github.com/yagikota/danewebperf/utils"
)

type measurementPattern string

var logger *slog.Logger

const (
	// path to output file
	resultDirectoryPath = "./../../result/pageloadtime"
	// input csv
	defaultInputCSV = "./../../dataset/test/test-data.csv"

	// these docker image should be built before running this program.
	unboundWithCacheImageName    = "unbound:with-cache"
	unboundWithoutCacheImageName = "unbound:without-cache"
	letsdaneImageName            = "letsdane:latest"
	firefoxHARImageName          = "firefox:latest"

	// pcap file path in the docker container
	firefoxPcapFilePath  = "/captured/firefox.pcap"
	unboundPcapFilePath  = "/captured/unbound.pcap"
	letsdanePcapFilePath = "/captured/letsdane.pcap"

	// DANE validation result file path in the docker container
	letsdaneDANEValidationResultFilePath = "/dane/cmd/letsdane/dane_validation_results.csv"

	// Measurement patterns
	withoutCacheWithoutDane measurementPattern = "without-cache-without-dane" // No cache, no DANE
	withCacheWithoutDane    measurementPattern = "with-cache-without-dane"    // Cache enabled, no DANE
	withoutCacheWithDane    measurementPattern = "without-cache-with-dane"    // No cache, DANE enabled
	withCacheWithDane       measurementPattern = "with-cache-with-dane"       // Cache and DANE enabled
)

type dockerRunOptions struct {
	ImageName     string
	NetWork       string
	ContainerName string
}

func newDockerRunOptions(imageName, network, containerName string) *dockerRunOptions {
	return &dockerRunOptions{
		ImageName:     imageName,
		NetWork:       network,
		ContainerName: containerName,
	}
}

type fireFoxHAROptions struct {
	Website       string
	ResolverIP    string
	ProxyHost     string
	DANE          bool
	FillCacheOnly bool
}

func newFireFoxHAROptions(website, resolverIP, proxyHost string, dane bool) *fireFoxHAROptions {
	return &fireFoxHAROptions{
		Website:       website,
		ResolverIP:    resolverIP,
		ProxyHost:     proxyHost,
		DANE:          dane,
		FillCacheOnly: false,
	}
}

type LetsdaneOptions struct {
	ResolverIP string
}

func newLetsdaneOptions(resolverIP string) *LetsdaneOptions {
	return &LetsdaneOptions{
		ResolverIP: resolverIP,
	}
}

type PcapOptions struct {
	ResultDirPath string
	PcapSuffix    string
}

func newPcapOptions(resultDirPath, pcapSuffix string) *PcapOptions {
	return &PcapOptions{
		ResultDirPath: resultDirPath,
		PcapSuffix:    pcapSuffix,
	}
}

type DANEValidationResultOpts struct {
	ResultDirPath    string
	ResultFileSuffix string
}

func NewDANEValidationResultOpts(resultDirPath, resultFileSuffix string) *DANEValidationResultOpts {
	return &DANEValidationResultOpts{
		ResultDirPath:    resultDirPath,
		ResultFileSuffix: resultFileSuffix,
	}
}

type commandOptions struct {
	LetsdaneDockerRunOpts    *dockerRunOptions
	LetsdaneOptions          *LetsdaneOptions
	HARDockerRunOpts         *dockerRunOptions
	HAROpts                  *fireFoxHAROptions
	UnboundDockerRunOpts     *dockerRunOptions
	PcapOpts                 *PcapOptions
	DANEValidationResultOpts *DANEValidationResultOpts
	Cache                    bool
}

func newCommandOptions(letsdaneDockerRunOpts *dockerRunOptions, letsdaneOpts *LetsdaneOptions, HARDockerRunOpts *dockerRunOptions, HAROpts *fireFoxHAROptions, unboundDockerOpts *dockerRunOptions, pcapOpts *PcapOptions, DANEValidationResultOpts *DANEValidationResultOpts, cache bool) *commandOptions {
	return &commandOptions{
		LetsdaneDockerRunOpts:    letsdaneDockerRunOpts,
		LetsdaneOptions:          letsdaneOpts,
		HARDockerRunOpts:         HARDockerRunOpts,
		HAROpts:                  HAROpts,
		UnboundDockerRunOpts:     unboundDockerOpts,
		PcapOpts:                 pcapOpts,
		DANEValidationResultOpts: DANEValidationResultOpts,
		Cache:                    cache,
	}
}

// createNetwork creates docker network for measurement.
//
// original command: docker network create [network name]
func createDockerNetwork(network string) error {
	if network == "" {
		logger.Warn("network name is empty")
		return nil
	}

	cmd := exec.Command("docker", "network", "create", network)
	logger.Info(fmt.Sprintf("command: %s", cmd.String()))

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		logger.Error(fmt.Sprintf("Stderr: %s", stderr.String()))
		return err
	}

	logger.Info(fmt.Sprintf("Stdout: %s", stdout.String()))
	return nil
}

// removeDockerNetwork removes docker network after finishing measurement.
//
// original command: docker network rm [network name]
func removeDockerNetwork(network string) error {
	cmd := exec.Command("docker", "network", "rm", network)
	logger.Info(fmt.Sprintf("command: %s", cmd.String()))

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		logger.Error(fmt.Sprintf("Stderr: %s", stderr.String()))
		return err
	}

	logger.Info(fmt.Sprintf("Stdout: %s", stdout.String()))
	return nil
}

// getContainerIP get container ip address from container name
//
// original command: docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' [container name]
func getContainerIP(containerName string) (string, error) {
	cmd := exec.Command("docker", "inspect", "-f", "{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}", containerName)
	logger.Info(fmt.Sprintf("command: %s", cmd.String()))

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		logger.Error(fmt.Sprintf("Stderr: %s", stderr.String()))
		return "", err
	}

	logger.Info(fmt.Sprintf("Stdout: %s", stdout.String()))
	return strings.TrimSpace(stdout.String()), nil
}

func runUnboundContainer(opts *commandOptions) error {
	dockerCmd := []string{"docker", "run", "--rm", "--network", opts.UnboundDockerRunOpts.NetWork, "--name", opts.UnboundDockerRunOpts.ContainerName, "-d", "-p", ":53/udp", "-p", ":53/tcp", opts.UnboundDockerRunOpts.ImageName}
	cmd := exec.Command(dockerCmd[0], dockerCmd[1:]...)
	logger.Info(fmt.Sprintf("command: %s", cmd.String()))

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		logger.Error(fmt.Sprintf("Stderr: %s", stderr.String()))
		return err
	}

	logger.Info(fmt.Sprintf("Stdout: %s", stdout.String()))
	return nil
}

// runLetsdaneContainer executes letsdane docker container, which is proxy server for firefox-har.
//
// original command: docker run --rm --network=[network name] --name [container name] -d [image name] -verbose -r [resolver ip] -cert /root/.letsdane/cert.crt -key /root/.letsdane/cert.key
func runLetsdaneContainer(opts *commandOptions) error {
	dockerCmd := []string{"docker", "run", "--network", opts.LetsdaneDockerRunOpts.NetWork, "--name", opts.LetsdaneDockerRunOpts.ContainerName, "-d", opts.LetsdaneDockerRunOpts.ImageName}
	letsdaneCmd := []string{"-verbose", "-r", opts.LetsdaneOptions.ResolverIP, "-cert", "/root/.letsdane/cert.crt", "-key", "/root/.letsdane/cert.key", "-skip-dnssec"}
	cmd := exec.Command(dockerCmd[0], append(dockerCmd[1:], letsdaneCmd...)...)
	logger.Info(fmt.Sprintf("command: %s", cmd.String()))

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		logger.Error(fmt.Sprintf("Stderr: %s", stderr.String()))
		return err
	}

	logger.Info(fmt.Sprintf("Stdout: %s", stdout.String()))
	return nil
}

func runLetsdaneContainerForFillCache(opts *commandOptions) error {
	dockerCmd := []string{"docker", "run", "--network", opts.LetsdaneDockerRunOpts.NetWork, "--name", opts.LetsdaneDockerRunOpts.ContainerName + "-fill-cache", "-d", opts.LetsdaneDockerRunOpts.ImageName}
	letsdaneCmd := []string{"-verbose", "-r", opts.LetsdaneOptions.ResolverIP, "-cert", "/root/.letsdane/cert.crt", "-key", "/root/.letsdane/cert.key"}
	cmd := exec.Command(dockerCmd[0], append(dockerCmd[1:], letsdaneCmd...)...)
	logger.Info(fmt.Sprintf("command: %s", cmd.String()))

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		logger.Error(fmt.Sprintf("Stderr: %s", stderr.String()))
		return err
	}

	logger.Info(fmt.Sprintf("Stdout: %s", stdout.String()))
	return nil
}

func startCapturePackets(containerName, pcapFilePath string) error {
	cmd := exec.Command("docker", "exec", "-d", containerName, "tcpdump", "-i", "any", "-w", pcapFilePath)
	logger.Info(fmt.Sprintf("command: %s", cmd.String()))

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Start()
	if err != nil {
		logger.Error(fmt.Sprintf("Stderr: %s", stderr.String()))
		return err
	}

	logger.Info(fmt.Sprintf("Stdout: %s", stdout.String()))
	return nil
}

// runFireFoxHAR executes firefox-har docker container, which runs Firefox and generates HAR file.
//
// original command: docker run --rm --network=[network name] --name [container name] [image name] https://www.torproject.org letsdane-www.torproject.org --dane
func runFireFoxHAR(opts *commandOptions) ([]byte, error) {
	dockerCmd := []string{"docker", "run", "--network", opts.HARDockerRunOpts.NetWork, "--name", opts.HARDockerRunOpts.ContainerName, opts.HARDockerRunOpts.ImageName}
	firefoxHARCmd := []string{opts.HAROpts.Website}
	if opts.HAROpts.DANE {
		firefoxHARCmd = append(firefoxHARCmd, "-dph", opts.HAROpts.ProxyHost)
		firefoxHARCmd = append(firefoxHARCmd, "--dane")
	} else {
		// Even if DANE is not used for this specific measurement, pageload_measure.py might need the resolver.
		// Also, providing non-DANE proxy for consistency, though it might not be used.
		firefoxHARCmd = append(firefoxHARCmd, "-ri", opts.HAROpts.ResolverIP)
	}
	// Add non-DANE proxy host regardless of DANE status, the python script will decide.
	firefoxHARCmd = append(firefoxHARCmd, "-ndph", "my-datadog-proxy")

	if opts.HAROpts.FillCacheOnly {
		firefoxHARCmd = append(firefoxHARCmd, "--fill_cache_only")
	}

	cmd := exec.Command(dockerCmd[0], append(dockerCmd[1:], firefoxHARCmd...)...)
	logger.Info(fmt.Sprintf("command: %s", cmd.String()))

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		logger.Error(fmt.Sprintf("Stderr: %s", stderr.String()))
		return nil, err
	}

	return stdout.Bytes(), nil
}

func runFireFoxHARForFillCache(opts *commandOptions) ([]byte, error) {
	dockerCmd := []string{"docker", "run", "--rm", "--network", opts.HARDockerRunOpts.NetWork, "--name", opts.HARDockerRunOpts.ContainerName + "-fill-cache", opts.HARDockerRunOpts.ImageName}
	firefoxHARCmd := []string{opts.HAROpts.Website}
	if opts.HAROpts.DANE {
		firefoxHARCmd = append(firefoxHARCmd, "-dph", opts.HAROpts.ProxyHost+"-fill-cache")
		firefoxHARCmd = append(firefoxHARCmd, "--dane")
	} else {
		firefoxHARCmd = append(firefoxHARCmd, "-ri", opts.HAROpts.ResolverIP)
	}
	// Add non-DANE proxy host regardless of DANE status for cache filling as well.
	firefoxHARCmd = append(firefoxHARCmd, "-ndph", "my-datadog-proxy")

	firefoxHARCmd = append(firefoxHARCmd, "--fill_cache_only")

	cmd := exec.Command(dockerCmd[0], append(dockerCmd[1:], firefoxHARCmd...)...)
	logger.Info(fmt.Sprintf("command: %s", cmd.String()))

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		logger.Error(fmt.Sprintf("Stderr: %s", stderr.String()))
		return nil, err
	}

	return stdout.Bytes(), nil
}

func removeContainer(containerName string) error {
	cmd := exec.Command("docker", "rm", containerName)
	logger.Info(fmt.Sprintf("command: %s", cmd.String()))

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		logger.Error(fmt.Sprintf("Stderr: %s", stderr.String()))
		return err
	}

	logger.Info(fmt.Sprintf("Stdout: %s", stdout.String()))
	return nil
}

func dockerCopy(containerName, srcPath, dstPath string) error {
	cmd := exec.Command("docker", "cp", containerName+":"+srcPath, dstPath)
	logger.Info(fmt.Sprintf("command: %s", cmd.String()))

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		logger.Error(fmt.Sprintf("Stderr: %s", stderr.String()))
		return err
	}

	logger.Info(fmt.Sprintf("Stdout: %s", stdout.String()))
	return nil
}

func stopContainer(containerName string) error {
	cmd := exec.Command("docker", "stop", containerName)
	logger.Info(fmt.Sprintf("command: %s", cmd.String()))

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		logger.Error(fmt.Sprintf("Stderr: %s", stderr.String()))
		return err
	}

	logger.Info(fmt.Sprintf("Stdout: %s", stdout.String()))
	return nil
}

func collectHAR(opts *commandOptions) ([]byte, error) {
	// 1. Create Docker network
	if err := createDockerNetwork(opts.HARDockerRunOpts.NetWork); err != nil {
		return nil, err
	}
	defer func() {
		logger.Info(fmt.Sprintf("remove network: %s", opts.HARDockerRunOpts.NetWork))
		if removeErr := removeDockerNetwork(opts.HARDockerRunOpts.NetWork); removeErr != nil {
			logger.Error(fmt.Sprintf("Failed to remove Docker network: %s", removeErr))
		}
	}()

	// 2. Run unbound
	if err := runUnboundContainer(opts); err != nil {
		return nil, err
	}
	defer func() {
		logger.Info(fmt.Sprintf("stop container: %s", opts.UnboundDockerRunOpts.ContainerName))
		if stopErr := stopContainer(opts.UnboundDockerRunOpts.ContainerName); stopErr != nil {
			logger.Error(fmt.Sprintf("Failed to stop Docker container: %s", stopErr))
		}
	}()

	// Get the IP address of the unbound
	unboundIP, err := getContainerIP(opts.UnboundDockerRunOpts.ContainerName)
	if err != nil {
		return nil, err
	}
	opts.HAROpts.ResolverIP = unboundIP
	if opts.HAROpts.DANE {
		opts.LetsdaneOptions.ResolverIP = unboundIP
	}

	// 3. fill cache before measuring page load time if cache is enabled
	if opts.Cache {
		if opts.HAROpts.DANE {
			if err := runLetsdaneContainerForFillCache(opts); err != nil {
				return nil, err
			}
			defer func() {
				if stopErr := stopContainer(opts.LetsdaneDockerRunOpts.ContainerName + "-fill-cache"); stopErr != nil {
					logger.Error(fmt.Sprintf("Failed to stop Docker container: %s", stopErr))
				}
				if err := removeContainer(opts.LetsdaneDockerRunOpts.ContainerName + "-fill-cache"); err != nil {
					logger.Error(fmt.Sprintf("Failed to remove Docker container: %s", err))
				}
			}()
		}

		if _, err := runFireFoxHARForFillCache(opts); err != nil {
			logger.Info(fmt.Sprintf("ignore this error when filling cache: %s", err))
		}

		logger.Info(fmt.Sprintf("finish filling cache: %s", opts.HAROpts.Website))
	}

	if err := startCapturePackets(opts.UnboundDockerRunOpts.ContainerName, unboundPcapFilePath); err != nil {
		logger.Error(fmt.Sprintf("Failed to start capturing packets in the unbound Docker container: %s", err))
		return nil, err
	}
	defer func() {
		outputFileName := "unbound" + opts.PcapOpts.PcapSuffix + ".pcap"
		logger.Info(fmt.Sprintf("copy pcap file: %s", outputFileName))
		if err := dockerCopy(opts.UnboundDockerRunOpts.ContainerName, unboundPcapFilePath, filepath.Join("./", opts.PcapOpts.ResultDirPath, outputFileName)); err != nil {
			logger.Error(fmt.Sprintf("Failed to copy pcap file: %s", err))
		}
	}()

	// 4. Run letsdane if DANE is enabled
	if opts.HAROpts.DANE {
		if err := runLetsdaneContainer(opts); err != nil {
			return nil, err
		}
		defer func() {
			// Stop and remove the letsdane Docker container
			logger.Info(fmt.Sprintf("stop container: %s", opts.LetsdaneDockerRunOpts.ContainerName))
			if stopErr := stopContainer(opts.LetsdaneDockerRunOpts.ContainerName); stopErr != nil {
				logger.Error(fmt.Sprintf("Failed to stop Docker container: %s", stopErr))
			}
			logger.Info(fmt.Sprintf("remove container: %s", opts.LetsdaneDockerRunOpts.ContainerName))
			if err := removeContainer(opts.LetsdaneDockerRunOpts.ContainerName); err != nil {
				logger.Error(fmt.Sprintf("Failed to remove Docker container: %s", err))
			}
		}()
		if err := startCapturePackets(opts.LetsdaneDockerRunOpts.ContainerName, letsdanePcapFilePath); err != nil {
			logger.Error(fmt.Sprintf("Failed to start capturing packets in the letsdane Docker container: %s", err))
			return nil, err
		}
		defer func() {
			outputFileName := "letsdane" + opts.PcapOpts.PcapSuffix + ".pcap"
			logger.Info(fmt.Sprintf("copy pcap file: %s", outputFileName))
			if err := dockerCopy(opts.LetsdaneDockerRunOpts.ContainerName, letsdanePcapFilePath, filepath.Join("./", opts.PcapOpts.ResultDirPath, outputFileName)); err != nil {
				logger.Error(fmt.Sprintf("Failed to copy pcap file: %s", err))
			}
		}()
		defer func() {
			outputFileName := "letsdane" + opts.DANEValidationResultOpts.ResultFileSuffix + ".csv"
			logger.Info(fmt.Sprintf("copy DANE validation result file: %s", outputFileName))
			if err := dockerCopy(opts.LetsdaneDockerRunOpts.ContainerName, letsdaneDANEValidationResultFilePath, filepath.Join("./", opts.DANEValidationResultOpts.ResultDirPath, outputFileName)); err != nil {
				logger.Error(fmt.Sprintf("Failed to copy DANE validation result file: %s", err))
			}
		}()
	}

	result, err := runFireFoxHAR(opts)
	// copy pcap file and remove container regardless of whether the measurement was successful or not.
	defer func() {
		logger.Info(fmt.Sprintf("remove container: %s", opts.HARDockerRunOpts.ContainerName))
		if err := removeContainer(opts.HARDockerRunOpts.ContainerName); err != nil {
			logger.Error(fmt.Sprintf("Failed to remove Docker container: %s", err))
		}
	}()
	defer func() {
		outputFileName := "firefox" + opts.PcapOpts.PcapSuffix + ".pcap"
		logger.Info(fmt.Sprintf("copy pcap file: %s", outputFileName))
		if err := dockerCopy(opts.HARDockerRunOpts.ContainerName, firefoxPcapFilePath, filepath.Join("./", opts.PcapOpts.ResultDirPath, outputFileName)); err != nil {
			logger.Error(fmt.Sprintf("Failed to copy pcap file: %s", err))
		}
	}()

	return result, err
}

func measurementPatternSuffix(cache, dane bool) string {
	var suffix string
	if !cache && !dane {
		suffix = "-" + string(withoutCacheWithoutDane)
	}
	if cache && !dane {
		suffix = "-" + string(withCacheWithoutDane)
	}
	if !cache && dane {
		suffix = "-" + string(withoutCacheWithDane)
	}
	if cache && dane {
		suffix = "-" + string(withCacheWithDane)
	}
	return suffix
}

func generateMeasurementID(record utils.Record, cache, dane bool) string {
	return record.Domain + measurementPatternSuffix(cache, dane)
}

func unboundDockerImage(cache bool) string {
	if cache {
		return unboundWithCacheImageName
	}
	return unboundWithoutCacheImageName
}

type HARFileContent struct {
	Directory string
	FileName  string
	Content   []byte
	Domain    string
}

// go run main.go -website example.com -cache -timeout 30 -dane -measurementID 1 -first 1 -last 100 -concurrency 10
func main() {
	logger = slog.New(slog.NewJSONHandler(os.Stdout, nil))

	start := time.Now()
	cache := flag.Bool("cache", false, "Enable DNS cache")
	dane := flag.Bool("dane", false, "Enable DANE")
	first := flag.Int("first", 1, "first index of Domain list")
	last := flag.Int("last", -1, "last index of Domain list. if -1, last index is last index of Domain list")
	subDirName := flag.String("subdirname", start.Format("2006-01-02-15-04-05"), "sub directory name")
	inputCSV := flag.String("inputCSV", defaultInputCSV, "input CSV path")
	concurrency := flag.Int("concurrency", 1, "number of goroutines to run at once")
	flag.Parse()

	logger.Info(fmt.Sprintf("measurement started at %s", start.Format("2006-01-02-15-04-05")))

	domainList, err := utils.ReadDomainListCSV(*inputCSV)
	if err != nil {
		log.Fatalln(err)
	}

	if *last == -1 {
		*last = len(domainList)
	}
	subsetDomainList := domainList[*first-1 : *last]

	// create directory for this measurement
	resultSubDirectoryPath := filepath.Join(resultDirectoryPath, *subDirName)

	if err := os.MkdirAll(resultSubDirectoryPath, 0755); err != nil {
		if !os.IsExist(err) {
			log.Fatalln(err)
		}
	}

	// execute in parallel
	logger.Info("start measuring page load time")

	var wg sync.WaitGroup
	sem := make(chan struct{}, *concurrency)
	harContentChan := make(chan HARFileContent, len(subsetDomainList))
	for index, record := range subsetDomainList {
		sem <- struct{}{}
		wg.Add(1)

		go func(index int, record utils.Record) {
			defer func() {
				<-sem
				wg.Done()
			}()

			outPutDir := filepath.Join(resultSubDirectoryPath, record.Domain) // ../../result/pageloadtime/1/example.com/
			if err := os.MkdirAll(outPutDir, 0755); err != nil {
				if !os.IsExist(err) {
					logger.Error("Failed to create directory:", err)
				}
			}

			// this resolver IP is overwritten by the IP address of the unbound Docker container.
			var resolverIP string
			network := strings.Join([]string{"network", generateMeasurementID(record, *cache, *dane)}, "-")
			unboundContainerName := strings.Join([]string{"unbound", generateMeasurementID(record, *cache, *dane)}, "-")
			unboundDockerOpts := newDockerRunOptions(unboundDockerImage(*cache), network, unboundContainerName)

			var proxyHost string
			var letsdaneDockerOpts *dockerRunOptions
			var letsdaneOpts *LetsdaneOptions
			if *dane {
				letsdaneContainerName := strings.Join([]string{"letsdane", generateMeasurementID(record, *cache, *dane)}, "-")
				letsdaneDockerOpts = newDockerRunOptions(letsdaneImageName, network, letsdaneContainerName)
				letsdaneOpts = newLetsdaneOptions(resolverIP)
				proxyHost = letsdaneContainerName
			}
			firefoxHARContainerName := strings.Join([]string{"firefox", generateMeasurementID(record, *cache, *dane)}, "-")
			HARDockerOpts := newDockerRunOptions(firefoxHARImageName, network, firefoxHARContainerName)
			HAROpts := newFireFoxHAROptions("https://"+record.Domain, resolverIP, proxyHost, *dane)
			pcapSuffix := "-" + generateMeasurementID(record, *cache, *dane)
			pcapOpts := newPcapOptions(outPutDir, pcapSuffix)

			DANEValidationResultSuffix := "-" + generateMeasurementID(record, *cache, *dane)
			DANEValidationResultOpts := NewDANEValidationResultOpts(outPutDir, DANEValidationResultSuffix)

			opts := newCommandOptions(letsdaneDockerOpts, letsdaneOpts, HARDockerOpts, HAROpts, unboundDockerOpts, pcapOpts, DANEValidationResultOpts, *cache)

			// collect HAR file
			content, err := collectHAR(opts)
			if err != nil {
				logger.Error(fmt.Sprintf("Failed to collect HAR file: %s", err))
			}

			outPutFileName := strings.Join([]string{generateMeasurementID(record, *cache, *dane), "har"}, ".") // example.com-with-cache-with-dane.har

			harContent := HARFileContent{
				Directory: outPutDir,
				FileName:  outPutFileName,
				Content:   content,
				Domain:    record.Domain,
			}

			harContentChan <- harContent
			logger.Info(fmt.Sprintf("finish measuring page load time for %d: %s", index+1, record.Domain))

		}(index, record)
	}

	go func() {
		defer close(harContentChan)
		wg.Wait()
	}()

	successResult := make([]string, 0)
	failedResult := make([]string, 0)
	domainPageLoadTimeMap := make(map[string]string)
	// write HAR file
	for content := range harContentChan {
		if len(content.Content) == 0 {
			logger.Info(fmt.Sprintf("Har file is empty: %s", content.FileName))
			failedResult = append(failedResult, content.Domain)
			domainPageLoadTimeMap[content.Domain] = ""
			continue
		}

		var harLog har.Log
		if err := json.Unmarshal(content.Content, &harLog); err != nil {
			logger.Error(fmt.Sprintf("Failed to unmarshal HAR file: %s", err))
			failedResult = append(failedResult, content.Domain)
			domainPageLoadTimeMap[content.Domain] = ""
			continue
		}
		har := har.Har{
			Log: harLog,
		}
		// drop each response content because it is too large size
		har.DropEachResponseContent()

		if !har.ValidPageLoadTime() {
			logger.Warn(fmt.Sprintf("Fail to get pageload time from HAR file: %s", content.FileName))
			failedResult = append(failedResult, content.Domain)
			domainPageLoadTimeMap[content.Domain] = ""
			continue
		}

		logger.Info(fmt.Sprintf("success to get pageload time from HAR file: %s", content.FileName))
		successResult = append(successResult, strings.TrimSuffix(content.FileName, filepath.Ext(content.FileName)))
		domainPageLoadTimeMap[content.Domain] = strconv.Itoa(har.OnLoadOfFirstPage())

		// export as har file
		if err := har.Save(filepath.Join(content.Directory, content.FileName)); err != nil {
			logger.Error(fmt.Sprintf("Failed to save HAR file as har: %s", err))
		}
		// save as csv
		csvHar := har.ConvertCSVFormat()
		if err := csvHar.SaveAsCSV(filepath.Join(content.Directory, strings.Join([]string{strings.TrimSuffix(content.FileName, filepath.Ext(content.FileName)), "csv"}, "."))); err != nil {
			logger.Error(fmt.Sprintf("Failed to save HAR file as csv: %s", err))
		}
	}

	// write page load time into csv
	pageLoadCSVFile := filepath.Join(resultSubDirectoryPath, "pageloadtime"+measurementPatternSuffix(*cache, *dane)+".csv")
	if err := utils.WritePageLoadTimeCSV(pageLoadCSVFile, domainPageLoadTimeMap, *cache, *dane); err != nil {
		logger.Error(fmt.Sprintf("Failed to write page load time into csv: %s", err))
	}

	logger.Info("finish measuring page load time")

	for _, result := range successResult {
		logger.Info(fmt.Sprintf("success: %s", result))
	}
	for _, result := range failedResult {
		logger.Info(fmt.Sprintf("failed: %s", result))
	}

	logger.Info(fmt.Sprintf("all: %d success: %d, failed: %d", len(subsetDomainList), len(successResult), len(failedResult)))

	logger.Info(fmt.Sprintf("elapsed time: %s", time.Since(start).String()))
}
