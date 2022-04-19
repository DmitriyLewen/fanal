package apk

import (
	"bufio"
	"context"
	"os"
	"regexp"
	"strings"

	"github.com/aquasecurity/fanal/analyzer"
	aos "github.com/aquasecurity/fanal/analyzer/os"
	"github.com/aquasecurity/fanal/types"
	ver "github.com/aquasecurity/go-version/pkg/version"
)

func init() {
	analyzer.RegisterAnalyzer(&secfixecRepoAnalyzer{})
}

const secfixecAnalyzerVersion = 1

var (
	requiredFilesRegexp    = regexp.MustCompile(`^/?etc/secfixes.d/([A-Za-z0-9_.-]+)$`)
	secfixecUrlParseRegexp = regexp.MustCompile(`(https*|ftp)://[0-9A-Za-z.-]+/v?([0-9A-Za-z_.-]+)/`)
)

type secfixecRepoAnalyzer struct{}

func (a secfixecRepoAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	scanner := bufio.NewScanner(input.Content)
	var osFamily, repoVer string

	// take osFamily from filePath
	f := requiredFilesRegexp.FindStringSubmatch(input.FilePath)
	if len(f) == 2 {
		osFamily = strings.ToLower(f[1])
	}

	for scanner.Scan() {
		line := scanner.Text()

		m := secfixecUrlParseRegexp.FindStringSubmatch(line)
		if len(m) != 3 {
			continue
		}
		newVersion := m[2]

		// Find max Release version
		switch {
		case repoVer == "":
			repoVer = newVersion
		case repoVer == "edge" || newVersion == "edge":
			repoVer = "edge"
		default:
			oldVer, err := ver.Parse(repoVer)
			if err != nil {
				continue
			}
			newVer, err := ver.Parse(newVersion)
			if err != nil {
				continue
			}

			// Take the maximum version in apk repositories
			if newVer.GreaterThan(oldVer) {
				repoVer = newVersion
			}
		}
	}

	// Currently, we support only Alpine Linux in apk repositories.
	if osFamily != aos.Alpine || repoVer == "" {
		return nil, nil
	}

	return &analyzer.AnalysisResult{
		Repository: &types.Repository{
			Family:  osFamily,
			Release: repoVer,
		},
	}, nil
}

func (a secfixecRepoAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return requiredFilesRegexp.MatchString(filePath)
}

func (a secfixecRepoAnalyzer) Type() analyzer.Type {
	return analyzer.TypeApkSecfixedRepo
}

func (a secfixecRepoAnalyzer) Version() int {
	return secfixecAnalyzerVersion
}
