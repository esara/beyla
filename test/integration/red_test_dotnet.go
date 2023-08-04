//go:build integration

package integration

import (
	"testing"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/ebpf-autoinstrument/test/integration/components/prom"
)

func testREDMetricsDotNetHTTP(t *testing.T) {
	for _, testCaseURL := range []string{
		"http://localhost:5267",
	} {
		t.Run(testCaseURL, func(t *testing.T) {
			waitForTestComponents(t, testCaseURL)
			testREDMetricsForNodeHTTPLibrary(t, testCaseURL, "dotnetserver") // reusing what we do for NodeJS
		})
	}
}

// Special test without checks for a peer address. With the async nature of SSL on .NET we can't always get
// this information
func testREDMetricsForNetHTTPSLibrary(t *testing.T, url string, comm string) {
	path := "/greeting"

	// Call 3 times the instrumented service, forcing it to:
	// - take at least 30ms to respond
	// - returning a 204 code
	for i := 0; i < 4; i++ {
		doHTTPGet(t, url+path, 200)
	}

	// Eventually, Prometheus would make this query visible
	pq := prom.Client{HostPort: prometheusHostPort}
	var results []prom.Result
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`http_server_duration_seconds_count{` +
			`http_method="GET",` +
			`http_status_code="200",` +
			`service_namespace="integration-test",` +
			`service_name="` + comm + `",` +
			`http_target="` + path + `"}`)
		require.NoError(t, err)
		require.Len(t, results, 1)
		if len(results) > 0 {
			res := results[0]
			require.Len(t, res.Value, 2)
			assert.LessOrEqual(t, "3", res.Value[1])
		}
	})
}
func testREDMetricsDotNetHTTPS(t *testing.T) {
	for _, testCaseURL := range []string{
		"https://localhost:7034",
	} {
		t.Run(testCaseURL, func(t *testing.T) {
			waitForTestComponents(t, testCaseURL)
			testREDMetricsForNetHTTPSLibrary(t, testCaseURL, "dotnetserver") // reusing what we do for NodeJS
		})
	}
}