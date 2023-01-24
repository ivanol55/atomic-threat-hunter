// Sets the package name for the main script
package main

// Imports necessary packages for the main logic loop to run the necessary helpers and tools based on script arguments
import (
	"atomic-threat-hunter/src/golang/functions/helpers/configManagement"
	"atomic-threat-hunter/src/golang/functions/helpers/generalHelp"
	"atomic-threat-hunter/src/golang/functions/helpers/greeting"
	"atomic-threat-hunter/src/golang/functions/helpers/requiredArgCount"
	"atomic-threat-hunter/src/golang/functions/scanner/reconaissance"
	"atomic-threat-hunter/src/golang/functions/scanner/scan"
	"atomic-threat-hunter/src/golang/functions/scanner/scannerHelp"
	"os"
)

// Function that runs when the program is started, executes the main application logic
func main() {
	// Show the application greeting with ascii art title
	greeting.ShowGreeting()
	// Check if enough args were provided. If not, the program shows an error and exits
	requiredArgCount.CheckForArgs(os.Args, 2)
	// Check which tool to run depending on the first script argument
	switch os.Args[1] {
	// If "help" is provided as the first script argument, show the application general help page and exit the program
	case "help":
		generalHelp.ShowHelp()
	// If "scan" is provided as the first script argument, run the security application logic check
	case "scan":
		// Check if the required amount of arguments were sent. If not, show an error to the user and exit the program
		requiredArgCount.CheckForArgs(os.Args, 4)
		// Retrieve profile data we'll use
		var profileName string = os.Args[3]
		var profile configManagement.Profile = configManagement.GetProfile(profileName)
		// check for the second provided argument to see which security report helper needs to be executed
		switch os.Args[2] {
		// If "help" is requested as the second program argument, display the security scan-specific help and exit the program
		case "help":
			scannerHelp.ShowHelp()
		// If "recon" is requested as the second program argument, run the reconaissance phase toolchain and store the targets in the system
		case "recon":
			reconaissance.RunRecon(profileName, profile)
			// If "vulns" is requested as the second program argument, generate a report with the currently stored targets in the system by running the scan phase
		case "vulns":
			scan.RunScan(profileName, profile)
		// If "full" is requested as the second program argument, run the reconaissance phase and generate a report with the
		case "full":
			reconaissance.RunRecon(profileName, profile)
			scan.RunScan(profileName, profile)
		// If the scan script is sent a non-supported argument, show the security scan-specific help and exit the program
		default:
			scannerHelp.ShowHelp()
		}
	// If the first argument doesn't match any supported arguments, show the general application help and exit the program
	default:
		generalHelp.ShowHelp()
	}
}
