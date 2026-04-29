package database

import (
	"regexp"
	"strings"
)

// piiColumnKeywords are column name fragments that suggest PII storage.
var piiColumnKeywords = []string{
	"ssn", "social_security", "tax_id", "sin", // government IDs
	"credit_card", "card_number", "cvv", "ccv", "pan", // payment
	"passport", "drivers_license", "license_number",
	"dob", "date_of_birth", "birth_date",
	"phone", "mobile", "cell_phone",
	"email", "email_address",
	"address", "street_address", "zip", "postal",
	"full_name", "first_name", "last_name", "surname",
	"gender", "race", "ethnicity", "religion",
	"ip_address", "geolocation", "gps",
	"medical_record", "diagnosis", "medication", "prescription",
	"salary", "income", "bank_account", "routing_number",
}

// IsPIIColumn reports whether a column name looks like it stores PII.
func IsPIIColumn(col string) bool {
	lower := strings.ToLower(col)
	for _, kw := range piiColumnKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// PII data patterns for row sampling
var (
	reSSN        = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	reEmail      = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	rePhone      = regexp.MustCompile(`\b(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b`)
	reCCVisa     = regexp.MustCompile(`\b4[0-9]{12}(?:[0-9]{3})?\b`)
	reCCMaster   = regexp.MustCompile(`\b5[1-5][0-9]{14}\b`)
	reCCAmex     = regexp.MustCompile(`\b3[47][0-9]{13}\b`)
)

// PIIPattern is a named pattern for detecting PII in raw text.
type PIIPattern struct {
	Label string
	Re    *regexp.Regexp
}

var PIIPatterns = []PIIPattern{
	{"SSN", reSSN},
	{"Email", reEmail},
	{"Phone", rePhone},
	{"Visa card number", reCCVisa},
	{"Mastercard number", reCCMaster},
	{"Amex card number", reCCAmex},
}

// luhn validates a digit string using the Luhn algorithm.
func luhn(s string) bool {
	sum := 0
	nDigits := len(s)
	parity := nDigits % 2
	for i, ch := range s {
		d := int(ch - '0')
		if i%2 == parity {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
	}
	return sum%10 == 0
}

// IsCreditCard returns true if the string passes the Luhn check.
func IsCreditCard(s string) bool {
	digits := regexp.MustCompile(`\D`).ReplaceAllString(s, "")
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	return luhn(digits)
}
