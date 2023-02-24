// Sets the package name to import from the helper runner
package subdomains

// Imports necessary packages for the functions to run the security scan phase
import (
	alertIntegrations "atomic-threat-hunter/src/golang/functions/alertIntegrations/sendAlert"
	"atomic-threat-hunter/src/golang/functions/helpers/configManagement"
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

// Main function that runs the rest of the helpers inside of this file. It handles scanning the existing targets for the given profile, processing the scan diff, and sending it to the proper alert target integrations
func CheckNewSubdomains(profileName string, profile configManagement.Profile) {
	// Checks if the target file exists first, in case we need to warn about running a scan first
	checkForTargets(profileName)
	// Checks if this is the first scan or if we need to process the difference between the last scan and this one
	var lastScanExists bool = checkForLastScan(profileName)
	// Handles creating a diff file, either just copying the original file if no previous file existed, or handling getting only the new results, and storing them inside of diff.txt
	createScanDiff(profileName, lastScanExists)
	// Send diff.txt data to the channels selected by the profile with their proper integration
	processScanDiff(profileName, profile)
}

// Check for the targets file for the selected profile
func checkForTargets(profileName string) {
	fmt.Println("Checking if targets are properly stored for scanning...")
	// Check if the targets file exists to use it in the security scanning task
	var checkFile string = "./scans/" + profileName + "/targets/targets.txt"
	_, err := os.Stat(checkFile)
	if err != nil {
		// If the scans file doesn't exist, inform the user
		fmt.Println("Targets file not found! Please prepare a proper target file for this profile first by running the reconaissance phase.")
		os.Exit(1)
	} else {
		// If the file exists, inform the user and continue with the process
		fmt.Println("Found target file! all clear for subdomain scanning with the selected profile.")
	}
}

// Check if we have a last scan stored. Return true or false if this scan exists or not for further branching decisions
func checkForLastScan(profileName string) bool {
	var checkFile string = "./scans/" + profileName + "/targets/last.txt"
	var lastScanExists bool
	_, err := os.Stat(checkFile)
	if err != nil {
		// Return false if the last.txt file doesn't exist
		fmt.Println("No last report found! We'll run the routine to report all new subdomains found.")
		lastScanExists = false
		return lastScanExists
	} else {
		// Return true if the last.txt file exists
		fmt.Println("Found older subdomain report from the last execution! We'll run a comparison and just report the difference so we avoid dobule alerts.")
		lastScanExists = true
		return lastScanExists
	}
}

// Create the diff.txt file from the target reports
func createScanDiff(profileName string, lastScanExists bool) {
	// Prepare the file references for all needed files
	var newScanFile string = "./scans/" + profileName + "/targets/targets.txt"
	var oldScanFile string = "./scans/" + profileName + "/targets/last.txt"
	var diffFile string = "./scans/" + profileName + "/targets/diff.txt"
	if lastScanExists == false {
		// If there is no older file, we have no old reference and all domains are new. Copy latest.txt to last.txt and diff.txt, then continue to alert handling
		fmt.Println("As no older scan existed, we're using this one as the first known result and send it to the proper destination.")
		newScanBuffer, _ := ioutil.ReadFile(newScanFile)
		ioutil.WriteFile(oldScanFile, newScanBuffer, os.ModePerm)
		ioutil.WriteFile(diffFile, newScanBuffer, os.ModePerm)
	} else {
		// If the last report still exists, we need to run a diff operation to create diff.txt with only the new alerts.
		fmt.Println("An older scan existed, so we're going to compile their differences to send them to the proper destination.")
		// Create an array with the contents of the old results file
		var oldScanFileContents []byte
		oldScanFileContents, _ = ioutil.ReadFile(oldScanFile)
		var oldScanFileBuf bytes.Buffer
		oldScanFileBuf.Write(oldScanFileContents)
		var oldScanFileString string = string(oldScanFileBuf.Bytes())
		var oldScanFileArray []string = strings.Split(oldScanFileString, "\n")
		// Create an array with the contents of the new results file
		var newScanFileContents []byte
		newScanFileContents, _ = ioutil.ReadFile(newScanFile)
		var newScanFileBuf bytes.Buffer
		newScanFileBuf.Write(newScanFileContents)
		var newScanFileString string = string(newScanFileBuf.Bytes())
		var newScanFileArray []string = strings.Split(newScanFileString, "\n")
		// Prepare a better set of arrays with the data to avoid comparing timestamps
		// Run the function to check if something on the new array is not on the old one, send it to the diff file
		generateDiffFile(oldScanFileArray, newScanFileArray, profileName)
	}
}

// Get the linted arrays we just generated with proper keys and a dummy value, check for new entries, and save them to diff.txt
func generateDiffFile(oldScanFileArray []string, newScanFileArray []string, profileName string) {
	// Prepare the comparation dictionary with all old keys (template id + matched URL), and values (stringified json we can unmarshal later)
	var oldEntriesDict map[string]bool = map[string]bool{}
	var oldEntryKeyName string
	for _, oldEntry := range oldScanFileArray {
		oldEntryKeyName = oldEntry
		oldEntriesDict[oldEntryKeyName] = true
	}
	// Prepare the same array with the values from the new scan, check if the key exists in the old scan, and if it doesn't, attach it to the diff array
	var diffEntries []string
	var newEntryKeyName string
	for _, newEntry := range newScanFileArray {
		newEntryKeyName = newEntry
		// If the key we'd use in the new scan does not exist in the old scan, it means it's a new finding, so we add it to the final array
		_, exists := oldEntriesDict[newEntryKeyName]
		if exists == false {
			diffEntries = append(diffEntries, newEntry)
		}
	}
	// Store every new entry as a newline-separated entry in a single string
	var diffEntriesString string
	for _, entry := range diffEntries {
		diffEntriesString = diffEntriesString + entry + "\n"
	}
	// Save the diff result to diff.txt file with the contents of the string we just built
	var diffBytes []byte
	var diffBuffer bytes.Buffer
	var diffFile *os.File
	var diffFileName string
	diffFileName = "./scans/" + profileName + "/targets/diff.txt"
	diffBytes = []byte(diffEntriesString)
	diffBuffer.Write(diffBytes)
	diffFile, _ = os.Create(diffFileName)
	diffFile.Write(diffBytes)
}

// Process the reports with every integration stated in the profile
func processScanDiff(profileName string, profile configManagement.Profile) {
	alertIntegrations.SendAlert(profileName, profile, "subdomains")
}
