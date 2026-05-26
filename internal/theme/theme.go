package theme

type Theme struct {
	Reset     string
	Bold      string
	Underline string
	Red       string
	Green     string
	Yellow    string
	Blue      string
	Magenta   string
	Cyan      string
	White     string
	Gray      string
}

var LightTheme = Theme{
	Reset:     "\033[0m",
	Bold:      "\033[1m",
	Underline: "\033[4m",
	Red:       "\033[31m",
	Green:     "\033[32m",
	Yellow:    "\033[33m",
	Blue:      "\033[34m",
	Magenta:   "\033[35m",
	Cyan:      "\033[36m",
	White:     "\033[37m",
	Gray:      "\033[90m",
}

var DarkTheme = Theme{
	Reset:     "\033[0m",
	Bold:      "\033[1m",
	Underline: "\033[4m",
	Red:       "\033[91m",
	Green:     "\033[92m",
	Yellow:    "\033[93m",
	Blue:      "\033[94m",
	Magenta:   "\033[95m",
	Cyan:      "\033[96m",
	White:     "\033[97m",
	Gray:      "\033[37m",
}

func Red(s string) string { return DarkTheme.Red + s + DarkTheme.Reset }
