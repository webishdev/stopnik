package cmd

import (
	"bufio"
	"fmt"
	"github.com/webishdev/stopnik/internal/crypto"
	"os"
)

func ReadPassword() {
	fmt.Printf("Password: ")
	passwordScanner := bufio.NewScanner(os.Stdin)
	passwordScanner.Scan()
	password := passwordScanner.Text()
	fmt.Printf("Salt: ")
	saltScanner := bufio.NewScanner(os.Stdin)
	saltScanner.Scan()
	salt := saltScanner.Text()
	result := crypto.Sha512SaltedHash(password, salt)
	fmt.Printf("Hashed value is: %s\n\n", result)
}
