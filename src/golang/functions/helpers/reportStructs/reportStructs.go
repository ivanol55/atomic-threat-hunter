// Sets the package name to import from the helper runner
package reportStructs

// Declares the base struct of the json file we want to process from Nuclei, for each entry inside of the txt file.
type Vulnerability struct {
	Template      string            `json:"template"`
	TemplateUrl   string            `json:"template-url"`
	TemplateId    string            `json:"template-id"`
	TemplatePath  string            `json:"template-path"`
	Info          VulnerabilityInfo `json:"info"`
	Type          string            `json:"type"`
	Host          string            `json:"host"`
	MatchedAt     string            `json:"matched-at"`
	Ip            string            `json:"ip"`
	Timestamp     string            `json:"timestamp"`
	CurlCommand   string            `json:"curl-command"`
	MatcherStatus bool              `json:"matcher-status"`
	MatchedLine   string            `json:"matched-line"`
}

// Declares the struct for vulnerability info, contained inside of the Vulnerability json entry
type VulnerabilityInfo struct {
	Name        string   `json:"name"`
	Author      []string `json:"author"`
	Tags        []string `json:"tags"`
	Description string   `json:"description"`
	Reference   []string `json:"reference"`
	Severity    string   `json:"severity"`
}
