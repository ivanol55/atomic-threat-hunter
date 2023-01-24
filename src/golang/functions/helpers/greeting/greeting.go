// Sets the package name to import from the helper runner
package greeting

// Imports necessary packages for the function to print text into the terminal
import (
	"fmt"
)

// Declares a function that prints a stylized application name and a welcome message
func ShowGreeting() {
	fmt.Println("")
	fmt.Println(" ########################################################################################################")
	fmt.Println(" ########################################################################################################")
	fmt.Println("        _                  _           _   _                    _        _                 _            ")
	fmt.Println("   __ _| |_ ___  _ __ ___ (_) ___     | |_| |__  _ __ ___  __ _| |_     | |__  _   _ _ __ | |_ ___ _ __ ")
	fmt.Println("  /  _` | __/ _ \\| '_ ` _ \\| |/ __|___| __| '_ \\| '__/ _ \\/ _` | __|____| '_ \\| | | | '_ \\| __/ _ \\ '__|")
	fmt.Println("  | (_| | || (_) | | | | | | | (_|____| |_| | | | | |  __/ (_| | ||_____| | | | |_| | | | | ||  __/ |   ")
	fmt.Println("  \\__,_|\\__\\____/|_| |_| |_|_|\\___|    \\__|_| |_|_|  \\___|\\__,_|\\__|    |_| |_|\\__,_|_| |_|\\__\\___|_|   ")
	fmt.Println("")
	fmt.Println(" ########################################################################################################")
	fmt.Println(" ########################################################################################################")
	fmt.Println("")
	fmt.Println("Welcome to atomic-threat-hunter! this is a helper tool used to generate on-demand reports for application vulnerabilities. Let's avoid incidents the fancy way!")
}
