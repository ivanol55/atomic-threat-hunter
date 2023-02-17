// Sets the package name to import from the helper runner
package alertIntegrations

// Imports necessary packages for the functions to trigger any necessary alert functions
import (
	"atomic-threat-hunter/src/golang/functions/alertIntegrations/datadog"
	"atomic-threat-hunter/src/golang/functions/helpers/configManagement"
	"fmt"
)

// Function that gathers the profile we selected and sends the latest diff we just generated to all the alert channels we have integrated in
func SendAlert(profileName string, profile configManagement.Profile, reportType string) {
	// Prepares all necessary variables to handle sending alerts to the proper alert integration
	var alertChannels []string
	switch reportType {
	case "vulnerabilities":
		alertChannels = profile.Channels.Vulnerabilities
	case "subdomains":
		alertChannels = profile.Channels.Subdomains
	}
	var alertChannel string
	// Initialize the map that stores the integrations function triggers
	var integrationsMapping map[string]func(string, string)
	integrationsMapping = make(map[string]func(string, string))
	// Supported integrations are added by key name here
	integrationsMapping["datadog"] = datadog.Notify
	// Create and run an anonymous function that is equal to whatever functions we want to run according to the requested integration channels
	var alertFunction func(string, string)
	for _, alertChannel = range alertChannels {
		fmt.Println("Sending alerts for the executed scan to " + alertChannel + "...")
		alertFunction = integrationsMapping[alertChannel]
		alertFunction(profileName, reportType)
	}
}
