package alpine

import (
	"bufio"
	"context"
	"github.com/Masterminds/semver"
	"golang.org/x/xerrors"
	"os"
	"regexp"

	"github.com/aquasecurity/fanal/analyzer"
	aos "github.com/aquasecurity/fanal/analyzer/os"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/fanal/utils"
)

func init() {
	analyzer.RegisterAnalyzer(&alpineApkOSAnalyzer{})
}

const apkRepositoriesVersion = 1

var apkRepositoriesRegexp = regexp.MustCompile("/alpine/v*([0-9A-Za-z_.-]+)/")

type alpineApkOSAnalyzer struct{}

func (a alpineApkOSAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	scanner := bufio.NewScanner(input.Content)
	osVersion := ""
	for scanner.Scan() {
		line := scanner.Text()

		version := apkRepositoriesRegexp.FindStringSubmatch(line)
		if len(version) == 2 {
			newVersion := version[1]
			switch {
			case osVersion == "":
				osVersion = newVersion
			case osVersion == "edge" || newVersion == "edge":
				osVersion = "edge"
			default:
				semverOld, _ := semver.NewVersion(osVersion)
				semverNew, _ := semver.NewVersion(newVersion)
				if semverOld.LessThan(semverNew) {
					osVersion = newVersion
				}
			}
		}
	}

	if osVersion != "" {
		return &analyzer.AnalysisResult{
			OS: &types.OS{Family: aos.Alpine, Name: osVersion, Priority: 1},
		}, nil
	}
	return nil, xerrors.Errorf("alpine: %w", aos.AnalyzeOSError)
}

func (a alpineApkOSAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return utils.StringInSlice(filePath, a.requiredFiles())
}

func (a alpineApkOSAnalyzer) requiredFiles() []string {
	return []string{"etc/apk/repositories"}
}

func (a alpineApkOSAnalyzer) Type() analyzer.Type {
	return analyzer.TypeAlpineApk
}

func (a alpineApkOSAnalyzer) Version() int {
	return apkRepositoriesVersion
}
