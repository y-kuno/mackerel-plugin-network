package mpnetwork

import (
	"flag"

	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"strconv"
	"strings"

	mp "github.com/mackerelio/go-mackerel-plugin"
	"github.com/mackerelio/golib/logging"
)

var logger = logging.GetLogger("metrics.plugin.network")

var (
	newLineByte = []byte("\n")
	colonByte   = []byte(":")
)

// file path
const (
	NetDev     = "/proc/net/dev"
	NetNetstat = "/proc/net/netstat"
	NetSnmp    = "/proc/net/snmp"
)

// NetworkPlugin mackerel plugin
type NetworkPlugin struct {
	Prefix string
}

// MetricKeyPrefix interface for PluginWithPrefix
func (p *NetworkPlugin) MetricKeyPrefix() string {
	if p.Prefix == "" {
		p.Prefix = "network"
	}
	return p.Prefix
}

// GraphDefinition interface for mackerelplugin
func (p *NetworkPlugin) GraphDefinition() map[string]mp.Graphs {
	labelPrefix := strings.Title(p.Prefix)
	return map[string]mp.Graphs{
		"interface.#": {
			Label: labelPrefix + " Interface",
			Unit:  "integer",
			Metrics: []mp.Metrics{
				{Name: "rxPackets", Label: "rxPackets", Diff: true},
				{Name: "rxErrors", Label: "rxErrors", Diff: true},
				{Name: "rxDropped", Label: "rxDropped", Diff: true},
				{Name: "rxOverruns", Label: "rxOverruns", Diff: true},
				{Name: "txPackets", Label: "txPackets", Diff: true},
				{Name: "txErrors", Label: "txErrors", Diff: true},
				{Name: "txDropped", Label: "txDropped", Diff: true},
				{Name: "txOverruns", Label: "txOverruns", Diff: true},
			},
		},
		"ip.statistic": {
			Label: labelPrefix + " IP Statistics",
			Unit:  "integer",
			Metrics: []mp.Metrics{
				{Name: "IpExtInCsumErrors", Label: "InCsumErrors", Diff: true},
			},
		},
		"tcp.backlog": {
			Label: labelPrefix + " TCP Backlog",
			Unit:  "integer",
			Metrics: []mp.Metrics{
				{Name: "TcpExtTCPBacklogDrop", Label: "Drop", Diff: true},
			},
		},
		"tcp.conn.state": {
			Label: labelPrefix + " Tcp Connection States",
			Unit:  "integer",
			Metrics: []mp.Metrics{
				{Name: "ESTAB", Label: "Established", Diff: false, Stacked: true},
				{Name: "SYN-SENT", Label: "Syn Sent", Diff: false, Stacked: true},
				{Name: "SYN-RECV", Label: "Syn Received", Diff: false, Stacked: true},
				{Name: "FIN-WAIT-1", Label: "Fin Wait 1", Diff: false, Stacked: true},
				{Name: "FIN-WAIT-2", Label: "Fin Wait 2", Diff: false, Stacked: true},
				{Name: "TIME-WAIT", Label: "Time Wait", Diff: false, Stacked: true},
				{Name: "UNCONN", Label: "Close", Diff: false, Stacked: true},
				{Name: "CLOSE-WAIT", Label: "Close Wait", Diff: false, Stacked: true},
				{Name: "LAST-ACK", Label: "Last Ack", Diff: false, Stacked: true},
				{Name: "LISTEN", Label: "Listen", Diff: false, Stacked: true},
				{Name: "CLOSING", Label: "Closing", Diff: false, Stacked: true},
				{Name: "UNKNOWN", Label: "Unknown", Diff: false, Stacked: true},
			},
		},
		"tcp.statistic": {
			Label: labelPrefix + " Tcp Statistics",
			Unit:  "integer",
			Metrics: []mp.Metrics{
				{Name: "TcpEstabResets", Label: "Received Reset", Diff: true},
				{Name: "TcpOutRsts", Label: "Sent Reset", Diff: true},
				{Name: "TcpRetransSegs", Label: "Retrans Segs", Diff: true},
			},
		},
		"tcp.syncookie": {
			Label: labelPrefix + " Tcp Syncookies",
			Unit:  "integer",
			Metrics: []mp.Metrics{
				{Name: "TcpExtSyncookiesFailed", Label: "Failed", Diff: true},
			},
		},
	}
}

// FetchMetrics interface for mackerelplugin
func (p *NetworkPlugin) FetchMetrics() (map[string]float64, error) {
	metrics := make(map[string]float64)

	if err := p.getProcDev(metrics); err != nil {
		logger.Warningf(err.Error())
	}
	if err := p.getProcNetstat(metrics); err != nil {
		logger.Warningf(err.Error())
	}
	if err := p.getProcSnmp(metrics); err != nil {
		logger.Warningf(err.Error())
	}
	if err := p.getNetworkStatistics(metrics); err != nil {
		logger.Warningf(err.Error())
	}

	return metrics, nil
}

func (p *NetworkPlugin) getProcDev(metrics map[string]float64) error {
	file, err := os.Open(NetDev)
	if err != nil {
		return err
	}
	defer file.Close()

	return p.parseProcDev(metrics, file)
}

func (p *NetworkPlugin) getProcNetstat(metrics map[string]float64) error {
	data, err := ioutil.ReadFile(NetNetstat)
	if err != nil {
		return err
	}
	return p.parseProcMetrics(metrics, data)
}

func (p *NetworkPlugin) getProcSnmp(metrics map[string]float64) error {
	data, err := ioutil.ReadFile(NetSnmp)
	if err != nil {
		return err
	}
	return p.parseProcMetrics(metrics, data)
}

func (p *NetworkPlugin) getNetworkStatistics(metrics map[string]float64) error {
	cmd := exec.Command("ss", "-nat")
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return err
	}

	return p.parseNetworkStatistics(metrics, out)
}

func (p *NetworkPlugin) parseProcDev(metrics map[string]float64, out io.Reader) error {
	scanner := bufio.NewScanner(out)
	for scanner.Scan() {
		kv := strings.SplitN(scanner.Text(), ":", 2)
		if len(kv) != 2 {
			continue
		}
		fields := strings.Fields(kv[1])
		if len(fields) < 16 {
			continue
		}
		name := strings.TrimSpace(kv[0])
		if name == "lo" {
			continue
		}
		rxPackets, err := strconv.ParseFloat(fields[1], 64)
		if err != nil {
			return fmt.Errorf("failed to parse rxPackets of %s", name)
		}
		rxErrors, err := strconv.ParseFloat(fields[2], 64)
		if err != nil {
			return fmt.Errorf("failed to parse rxErrors of %s", name)
		}
		rxDropped, err := strconv.ParseFloat(fields[3], 64)
		if err != nil {
			return fmt.Errorf("failed to parse rxDropped of %s", name)
		}
		rxOverruns, err := strconv.ParseFloat(fields[4], 64)
		if err != nil {
			return fmt.Errorf("failed to parse rxOverruns of %s", name)
		}
		txPackets, err := strconv.ParseFloat(fields[9], 64)
		if err != nil {
			return fmt.Errorf("failed to parse txPackets of %s", name)
		}
		txErrors, err := strconv.ParseFloat(fields[10], 64)
		if err != nil {
			return fmt.Errorf("failed to parse txErrors of %s", name)
		}
		txDropped, err := strconv.ParseFloat(fields[11], 64)
		if err != nil {
			return fmt.Errorf("failed to parse txDropped of %s", name)
		}
		txOverruns, err := strconv.ParseFloat(fields[12], 64)
		if err != nil {
			return fmt.Errorf("failed to parse txOverruns of %s", name)
		}

		metrics["interface."+name+".rxPackets"] = rxPackets
		metrics["interface."+name+".rxErrors"] = rxErrors
		metrics["interface."+name+".rxDropped"] = rxDropped
		metrics["interface."+name+".rxOverruns"] = rxOverruns
		metrics["interface."+name+".txPackets"] = txPackets
		metrics["interface."+name+".txErrors"] = txErrors
		metrics["interface."+name+".txDropped"] = txDropped
		metrics["interface."+name+".txOverruns"] = txOverruns
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan error for /proc/net/dev: %s", err)
	}
	return nil
}

func (p *NetworkPlugin) parseProcMetrics(metrics map[string]float64, data []byte) error {
	// split the lines by newline
	lines := bytes.Split(data, newLineByte)
	// iterate over lines, take 2 lines each time
	// first line contains header names
	// second line contains values
	for i := 0; i < len(lines); i = i + 2 {
		if len(lines[i]) == 0 {
			continue
		}

		headers := bytes.Fields(lines[i])
		prefix := bytes.TrimSuffix(headers[0], colonByte)
		values := bytes.Fields(lines[i+1])

		for j := 1; j < len(headers); j++ {
			value, err := strconv.ParseFloat(string(values[j]), 64)
			if err != nil {
				return err
			}
			metrics[string(prefix)+string(headers[j])] = value
		}
	}
	return nil
}

func (p *NetworkPlugin) parseNetworkStatistics(metrics map[string]float64, out io.Reader) error {
	scanner := bufio.NewScanner(out)
	for scanner.Scan() {
		line := scanner.Text()
		record := strings.Fields(line)
		if record[0] == "State" {
			continue
		}
		value, _ := metrics[record[0]]
		metrics[record[0]] = value + 1
	}
	return nil
}

// Do the plugin
func Do() {
	optPrefix := flag.String("metric-key-prefix", "", "Metric key prefix")
	optTempfile := flag.String("tempfile", "", "Temp file name")
	flag.Parse()
	plugin := mp.NewMackerelPlugin(&NetworkPlugin{
		Prefix: *optPrefix,
	})
	plugin.Tempfile = *optTempfile
	plugin.Run()
}
