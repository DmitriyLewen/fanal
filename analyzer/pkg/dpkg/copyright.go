package dpkg

import (
	"bufio"
	"io"
	"io/ioutil"
	"regexp"
	"strings"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/types"
	classifier "github.com/google/licenseclassifier/v2/assets"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"
)

const LicenseAdder = "dpkg-license-adder"

var (
	cl, _                        = classifier.DefaultClassifier()
	copyrightFileRegexp          = regexp.MustCompile(`^usr/share/doc/([0-9A-Za-z_.-]+)/copyright$`)
	commonLicenseReferenceRegexp = regexp.MustCompile(`/?usr/share/common-licenses/([0-9A-Za-z_.+-]+[0-9A-Za-z+])`)
)

type License struct {
	Pkg      string
	Licenses string
}

// parseCopyrightFile parses /usr/share/doc/*/copyright files
func parseCopyrightFile(input analyzer.AnalysisInput, scanner *bufio.Scanner) (*analyzer.AnalysisResult, error) {
	var licenses []string
	buf, err := ioutil.ReadAll(input.Content) // save stream to buffer for use at github.com/google/licenseclassifier
	if err != nil {
		return nil, xerrors.Errorf("unable to read content from %q: %w", input.FilePath, err)
	}
	if _, err := input.Content.Seek(0, io.SeekStart); err != nil { // rewind the reader to the beginning of the stream after saving
		return nil, xerrors.Errorf("unable to rewind reader for %q file: %w", input.FilePath, err)
	}

	for scanner.Scan() {
		line := scanner.Text()

		// "License: *" pattern is used
		if strings.HasPrefix(line, "License:") {
			l := strings.TrimSpace(line[8:])
			if !slices.Contains(licenses, l) {
				licenses = append(licenses, l)
			}
		} else {
			// Common license pattern is used
			license := commonLicenseReferenceRegexp.FindStringSubmatch(line)
			if len(license) == 2 && !slices.Contains(licenses, license[1]) {
				licenses = append(licenses, license[1])
			}
		}
	}

	// Use 'github.com/google/licenseclassifier' for find licenses
	result := cl.Match(buf)
	for _, match := range result.Matches {
		if !slices.Contains(licenses, match.Name) {
			licenses = append(licenses, match.Name)
		}
	}

	licensesStr := strings.Join(licenses, ", ")
	if licensesStr == "" {
		licensesStr = "Unknown"
	}

	return &analyzer.AnalysisResult{
		CustomResources: []types.CustomResource{
			{
				Type:     LicenseAdder,
				FilePath: getPkgNameFromLicenseFilePath(input.FilePath),
				Data:     licensesStr,
			},
		},
	}, nil
}

func isLicenseFile(filePath string) bool {
	return copyrightFileRegexp.MatchString(filePath)
}

func getPkgNameFromLicenseFilePath(filePath string) string {
	pkgName := copyrightFileRegexp.FindStringSubmatch(filePath)
	if len(pkgName) == 2 {
		return pkgName[1]
	}
	return ""
}
