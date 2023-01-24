// Sets the package name to import from the helper runner
package datadog

// Imports necessary packages for the functions to run the security scan phase
import (
	"atomic-threat-hunter/src/golang/functions/helpers/configManagement"
	"atomic-threat-hunter/src/golang/functions/helpers/reportStructs"
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

// Prepare the datadog request struct where we'll store all info and marshal it to send the json request with the log
type DatadogRequest struct {
	DdSource string                      `json:"ddsource"`
	DdTags   string                      `json:"ddtags"`
	Hostname string                      `json:"hostname"`
	Message  reportStructs.Vulnerability `json:"Message"`
	Service  string                      `json:"service"`
}

func Notify(profileName string) {
	fmt.Println("Sending newly discovered vulnerabilities to Datadog...")
	// Prepare all necessary variables for this alert query sending from the integration configuration
	var ddIntegrationObj configManagement.Integration
	ddIntegrationObj = configManagement.GetIntegrations()
	var ddApiKey string = ddIntegrationObj.Datadog.DdApiKey
	var endpoint string = ddIntegrationObj.Datadog.Endpoint
	// Read the data stored inside of diff.json into the string array diffScanFileArray
	var diffScanFile string = "./scans/" + profileName + "/results/diff.txt"
	var diffScanFileContents []byte
	diffScanFileContents, _ = ioutil.ReadFile(diffScanFile)
	var diffScanFileBuf bytes.Buffer
	diffScanFileBuf.Write(diffScanFileContents)
	var diffScanFileString string = string(diffScanFileBuf.Bytes())
	var diffScanFileArray []string = strings.Split(diffScanFileString, "\n")
	diffScanFileArray = diffScanFileArray[:len(diffScanFileArray)-2]
	// Prepare variables to properly build and send requests into Datadog
	var ddPostRequest DatadogRequest
	var ddPostRequestBody []byte
	var ddPostRequestBodyBuff bytes.Buffer
	var scanResultEntry string
	var scanResultStruct reportStructs.Vulnerability
	var ddRequestObject *http.Request
	var ddRequestClient *http.Client
	// Send each diff entry to Datadog in a POST request
	for _, scanResultEntry = range diffScanFileArray {
		// Unmarshal the scanResult entry json into the scanResult struct we store inside Message, pass the rest of the necessary values Datadog needs for metadata
		json.Unmarshal([]byte(scanResultEntry), &scanResultStruct)
		ddPostRequest = DatadogRequest{DdSource: "atomic-threat-hunter", DdTags: "profile:" + profileName, Hostname: "atomic-threat-hunter-" + profileName, Message: scanResultStruct, Service: "atomic-threat-hunter"}
		// Marshal the request we just built from struct to a json byte array
		ddPostRequestBody, _ = json.Marshal(ddPostRequest)
		// Prepare the request object we'll send to Datadog as a POST, to the logs endpoint, with the contents of the buffer we write
		ddPostRequestBodyBuff.Write(ddPostRequestBody)
		ddRequestObject, _ = http.NewRequest("POST", endpoint, &ddPostRequestBodyBuff)
		// Add the headers for the request to be parsed properly, the content-type json header as we are parsing a valid json, and the datadog api key for authentication
		ddRequestObject.Header.Add("Content-Type", "application/json")
		ddRequestObject.Header.Add("DD-API-KEY", ddApiKey)
		// Create the request client and execute the request we just built
		ddRequestClient = &http.Client{}
		ddRequestClient.Do(ddRequestObject)
	}
}
