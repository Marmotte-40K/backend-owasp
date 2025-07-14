package pkg

import "regexp"

// StripHTMLTags removes all HTML tags from a string.
func StripHTMLTags(input string) string {
	re := regexp.MustCompile(`<.*?>`)
	return re.ReplaceAllString(input, "")
}
