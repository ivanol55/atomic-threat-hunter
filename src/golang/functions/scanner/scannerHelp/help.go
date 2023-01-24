// Sets the package name to import from the helper runner
package scannerHelp

// Imports necessary packages for the function to print text into the console
import (
	"fmt"
)

// Declare a function to show help for the infrastructure commandlet
func ShowHelp() {
	fmt.Println("This is the application security scanner help! Here's the options available for you under 'scan':")
	fmt.Println("    - 'help' will display this help page again.")
	fmt.Println("    - 'recon [profile]' will run a reconaissance task on the targets specified in the profile that you provide")
	fmt.Println("    - 'vulns [profile]' will run a vulnerabiility scan that targets the existing target file for that profile")
	fmt.Println("    - 'full [profile]' will run a reconaissance task in the specified targets, then do a vulnerability scan against those targets")
	fmt.Println("")
}
