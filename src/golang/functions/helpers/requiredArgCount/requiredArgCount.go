// Sets the package name to import from the helper runner
package requiredArgCount

// Imports necessary packages for the function to print text into the terminal and run OS tasks, in this case, to close the program
import (
	"fmt"
	"os"
)

// Declares a function that passes in an argument list and a number of required args to check if the count is correct
func CheckForArgs(args []string, requiredCount int) {
	// Stores the argument count inside the variable to compare it to the number of required arguments
	var argumentCount int = len(args)
	// If the argument count is not the expected one, raises this issue and gracefully stops the program
	if argumentCount < requiredCount {
		fmt.Println("")
		fmt.Println("Seems like no arguments were provided for the script! Please check for the proper 'help' usage page to learn more.")
		os.Exit(0)
	}
}
