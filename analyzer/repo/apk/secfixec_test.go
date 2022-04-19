package apk

import (
	"context"
	"strings"
	"testing"

	"github.com/aquasecurity/fanal/analyzer"
	aos "github.com/aquasecurity/fanal/analyzer/os"
	"github.com/aquasecurity/fanal/types"
	"github.com/stretchr/testify/assert"
)

func TestSecfixecRepoAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name    string
		input   analyzer.AnalysisInput
		want    *analyzer.AnalysisResult
		wantErr string
	}{
		{
			name: "alpine",
			input: analyzer.AnalysisInput{
				FilePath: "/etc/secfixes.d/alpine",
				Content:  strings.NewReader("https://secdb.alpinelinux.org/edge/main.json"),
			},
			want: &analyzer.AnalysisResult{
				Repository: &types.Repository{Family: aos.Alpine, Release: "edge"},
			},
		},
		{
			name: "repository has 'http' schema",
			input: analyzer.AnalysisInput{
				FilePath: "/etc/secfixes.d/alpine",
				Content:  strings.NewReader("http://secdb.alpinelinux.org/v3.7/main.json"),
			},
			want: &analyzer.AnalysisResult{
				Repository: &types.Repository{Family: aos.Alpine, Release: "3.7"},
			},
		},
		{
			name: "repository has 'https' schema",
			input: analyzer.AnalysisInput{
				FilePath: "/etc/secfixes.d/alpine",
				Content:  strings.NewReader("https://secdb.alpinelinux.org/3.15/main.json"),
			},
			want: &analyzer.AnalysisResult{
				Repository: &types.Repository{Family: aos.Alpine, Release: "3.15"},
			},
		},
		{
			name: "repository has 'ftp' schema",
			input: analyzer.AnalysisInput{
				FilePath: "/etc/secfixes.d/alpine",
				Content:  strings.NewReader("ftp://secdb.alpinelinux.org/v2.6/main.json"),
			},
			want: &analyzer.AnalysisResult{
				Repository: &types.Repository{Family: aos.Alpine, Release: "2.6"},
			},
		},
		{
			name: "edge version",
			input: analyzer.AnalysisInput{
				FilePath: "/etc/secfixes.d/alpine",
				Content:  strings.NewReader("https://secdb.alpinelinux.org/edge/main.json"),
			},
			want: &analyzer.AnalysisResult{
				Repository: &types.Repository{Family: aos.Alpine, Release: "edge"},
			},
		},
		{
			name: "happy path. 'etc/apk/repositories' contains some line with v* versions",
			input: analyzer.AnalysisInput{
				FilePath: "/etc/secfixes.d/alpine",
				Content: strings.NewReader(`https://secdb.alpinelinux.org/v3.1/main.json

https://secdb.alpinelinux.org/v3.10/main.json
`),
			},
			want: &analyzer.AnalysisResult{
				Repository: &types.Repository{Family: aos.Alpine, Release: "3.10"},
			},
		},
		{
			name: "multiple v* versions",
			input: analyzer.AnalysisInput{
				FilePath: "/etc/secfixes.d/alpine",
				Content: strings.NewReader(`https://secdb.alpinelinux.org/v3.10/main.json
https://secdb.alpinelinux.org/v3.1/main.json
`),
			},
			want: &analyzer.AnalysisResult{
				Repository: &types.Repository{Family: aos.Alpine, Release: "3.10"},
			},
		},
		{
			name: "multiple v* and edge versions",
			input: analyzer.AnalysisInput{
				FilePath: "/etc/secfixes.d/alpine",
				Content: strings.NewReader(`https://secdb.alpinelinux.org/edge/main.json
https://secdb.alpinelinux.org/v3.10/main.json
`),
			},
			want: &analyzer.AnalysisResult{
				Repository: &types.Repository{Family: aos.Alpine, Release: "edge"},
			},
		},
		{
			name: "sad path",
			input: analyzer.AnalysisInput{
				FilePath: "/etc/secfixes.d/alpine",
				Content:  strings.NewReader("https://secdb.alpinelinux.org//edge/main.json"),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			a := secfixecRepoAnalyzer{}
			got, err := a.Analyze(context.Background(), test.input)

			if test.wantErr != "" {
				assert.Error(t, err)
				assert.Equal(t, test.wantErr, err.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, test.want, got)
			}

		})
	}
}
