// Sets the package name to import from the helper runner
package generalHelp

// Imports necessary packages for the function to print text into the terminal
import (
	"fmt"
)

// Declares a function that prints the general system help
func ShowHelp() {
	fmt.Println("This tool offers several scanning options depending on your needs. Scan your manually stated targets, do target discovery over a set, or run a full routine.")
	fmt.Println("    - 'help' will show this help page in case you need it again")
	fmt.Println("    - 'scan' will allow you to run the scans against your desired targets for any profiles you have configured. You can check its own help page for further details.")
}
