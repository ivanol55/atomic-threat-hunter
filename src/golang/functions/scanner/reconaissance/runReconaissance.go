// Sets the package name to import from the helper runner
package reconaissance

// Imports necessary packages for the functions to run the reconnaissance phase
import (
	"atomic-threat-hunter/src/golang/functions/helpers/configManagement"
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
)

// Declares a function that executes the different helpers required in order passing and storing the proper arguments. Each function is explained further down.
func RunRecon(profileName string, profile configManagement.Profile) {
	directorySetup(profileName)
	enumerateDomains(profileName, profile)
	var cleanTargetList []string = lintEnumeration(profileName)
	filterAliveTargets(profileName, cleanTargetList)
	checkDomainSecurity(profileName, cleanTargetList)
	cleanupUnnecessaryFiles(profileName)
}

// Create the necessary directories on the system to store a profile's targets and results
func directorySetup(profileName string) {
	fmt.Println("Creating source folder in case it doesn't exist...")
	var profilePath string = "./scans/" + profileName
	_ = os.Mkdir(profilePath, os.ModePerm)
	fmt.Println("Creating targets and results folders in case they don't exist...")
	var targetsPath string = profilePath + "/targets"
	_ = os.Mkdir(targetsPath, os.ModePerm)
	var resultsPath string = profilePath + "/results"
	_ = os.Mkdir(resultsPath, os.ModePerm)
}

// Enumerate target domains and store results in their proper files
func enumerateDomains(profileName string, profile configManagement.Profile) {
	// Store the domains array in a single comma-separated string
	var domainList []string = profile.Targets
	var domainWithCommas string
	var domain string
	for _, domain = range domainList {
		domainWithCommas = domainWithCommas + domain + ","
	}
	// Clears the last comma as it can cause trouble
	domainWithCommas = strings.TrimSuffix(domainWithCommas, ",")
	// Run subfinder to enumerate potential targets
	fmt.Println("Enumerating domains with subfinder...")
	var command string = "subfinder -d " + domainWithCommas + " -o ./scans/" + profileName + "/targets/subfinder.txt"
	var commandObject = exec.Command("sh", "-c", command)
	commandObject.Run()
	// Run amass to enumerate potential targets
	fmt.Println("Enumerate domains with amass...")
	command = "amass enum -d " + domainWithCommas + " -o ./scans/" + profileName + "/targets/amass.txt"
	commandObject = exec.Command("sh", "-c", command)
	commandObject.Run()
}

// Lint and consolidate enumeration results, removing duplicates and storing the results in a buffer we return
func lintEnumeration(profileName string) []string {
	// Prepare all necessary variables for the task
	var filesList []string
	var subfinderFile string = "./scans/" + profileName + "/targets/subfinder.txt"
	var amassFile string = "./scans/" + profileName + "/targets/amass.txt"
	filesList = append(filesList, subfinderFile)
	filesList = append(filesList, amassFile)
	// Add contents of all scan files to a buffer
	fmt.Println("Combining the results from the scans...")
	var bufFileContents bytes.Buffer
	var file string
	var fileContents []byte
	for _, file = range filesList {
		fileContents, _ = ioutil.ReadFile(file)
		bufFileContents.Write(fileContents)
	}
	// Convert the buffer contents to an array of strings we can handle on loops
	var bufferString string = string(bufFileContents.Bytes())
	var bufferList []string = strings.Split(bufferString, "\n")
	bufferList = bufferList[:len(bufferList)-1]
	// Prepare to remove duplicates and store one occurrence of each entry into a final array we can return
	var lintedTargetList []string
	var lintedTarget string
	var occurrences int
	var checkedTarget string
	// Iterate over every entry in the list we consolidated from all the reconnaissance results, which has duplicates
	fmt.Println("Removing result duplicates...")
	for _, lintedTarget = range bufferList {
		// Reset the occurrences finding, assuming we have found the first occurrence (lintedTarget)
		occurrences = 1
		// Check the final array for copies of the current lintedTarget
		for _, checkedTarget = range lintedTargetList {
			// if lintedTarget is found inside of the lintedTargetList, add an occurrence
			if lintedTarget == checkedTarget {
				occurrences = occurrences + 1
			}
		}
		// If we have not found any new occurrences, it means the lintedTarget is not in the final array, so we add it
		if occurrences == 1 {
			lintedTargetList = append(lintedTargetList, lintedTarget)
		}
	}
	return lintedTargetList
}

// Function that, given the linted list of targets for the profile, checks if the targets are actually alive and weeds out dead, old domains
func filterAliveTargets(profileName string, cleanTargetList []string) {
	// Set up the domain comma-separated list string to use in the checker command
	var domainString string
	var domainFromList string
	for _, domainFromList = range cleanTargetList {
		domainString = domainString + domainFromList + ","
	}
	// Clears the last comma as it can cause trouble
	domainString = strings.TrimSuffix(domainString, ",")
	// Use httpx to test if the target domains we discovered are alive and store them inside of a targets file
	fmt.Println("Checking what targets are actually active...")
	var command string = "httpx -u " + domainString + " -o ./scans/" + profileName + "/targets/targets.txt"
	var commandObject = exec.Command("sh", "-c", command)
	commandObject.Run()
}

// Function that checks the security of the discovered domains using Nmap, Nikto, and OWASP ZAP
func checkDomainSecurity(profileName string, cleanTargetList []string) {
	fmt.Println("Checking the security of discovered domains...")
	for _, domain := range cleanTargetList {
		fmt.Println("Checking domain:", domain)
		// Run Nmap scan
		nmapCommand := exec.Command("nmap", "-p 80,443", domain)
		nmapOutput, err := nmapCommand.Output()
		if err != nil {
			fmt.Println("Error running Nmap scan:", err)
		} else {
			fmt.Println("Nmap output for", domain, ":\n", string(nmapOutput))
		}

		// Run Nikto scan
		niktoCommand := exec.Command("nikto", "-h", domain)
		niktoOutput, err := niktoCommand.Output()
		if err != nil {
			fmt.Println("Error running Nikto scan:", err)
		} else {
			fmt.Println("Nikto output for", domain, ":\n", string(niktoOutput))
		}

		// Run OWASP ZAP scan
		owaspZapCommand := exec.Command("zap-cli", "quick-scan", "-t", domain)
		owaspZapOutput, err := owaspZapCommand.Output()
		if err != nil {
			fmt.Println("Error running OWASP ZAP scan:", err)
		} else {
			fmt.Println("OWASP ZAP output for", domain, ":\n", string(owaspZapOutput))
		}
	}
}

// Function that analyzes the DNS configuration for the discovered domains
func analyzeDNSConfiguration(profileName string, cleanTargetList []string) {
	fmt.Println("Analyzing DNS configuration for discovered domains...")
	for _, domain := range cleanTargetList {
		fmt.Println("Analyzing domain:", domain)

		// Run DNS reconnaissance using dig command
		digCommand := exec.Command("dig", domain)
		digOutput, err := digCommand.Output()
		if err != nil {
			fmt.Println("Error running dig command:", err)
		} else {
			fmt.Println("DNS reconnaissance output for", domain, ":\n", string(digOutput))
		}

		// Run DNSSEC verification using dig command
		dnssecCommand := exec.Command("dig", "+dnssec", domain)
		dnssecOutput, err := dnssecCommand.Output()
		if err != nil {
			fmt.Println("Error running DNSSEC verification:", err)
		} else {
			fmt.Println("DNSSEC verification output for", domain, ":\n", string(dnssecOutput))
		}

		// Run DNS zone transfer using dig command
		zoneTransferCommand := exec.Command("dig", "AXFR", domain)
		zoneTransferOutput, err := zoneTransferCommand.Output()
		if err != nil {
			fmt.Println("Error running DNS zone transfer:", err)
		} else {
			fmt.Println("DNS zone transfer output for", domain, ":\n", string(zoneTransferOutput))
		}
	}
}

// After finishing the reconnaissance phase, clean out the unnecessary files from the system
func cleanupUnnecessaryFiles(profileName string) {
	fmt.Println("Reconnaissance phase complete! Clearing unnecessary report files...")
	var fileToRemove string = "./scans/" + profileName + "/targets/subfinder.txt"
	_ = os.Remove(fileToRemove)
	fileToRemove = "./scans/" + profileName + "/targets/amass.txt"
	_ = os.Remove(fileToRemove)
	fileToRemove = "./scans/" + profileName + "/targets/linted-targets.txt"
	_ = os.Remove(fileToRemove)
}
