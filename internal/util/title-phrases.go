// all phrases you see in the terminal are stored here :)

package util

import "math/rand"

var titlePhrasesSlice = []string{
	"Did you have your coffee yet?",
	"I'm proud of you.",
	"OpenSSH is more open than secure...",
	"It's not a bug, it's an undisclosed feature.",
	"Trust no one, not even localhost.",
	"Your password is in rockyou.txt, isn't it?",
	"Patch Tuesday? More like Panic Tuesday.",
	"chmod 777 and pray.",
	"It's always DNS.",
	"The attacker is coming from inside the subnet.",
	"We don't have a breach. We have an unplanned data sharing event.",
	"Zero-day? More like zero-accountability.",
	"Reading logs at 3am builds character.",
	"sudo make me a sandwich.",
	"The firewall is just a suggestion.",
	"rm -rf /problems",
	"Security through obscurity is still obscurity.",
	"Have you tried turning it off and not turning it back on?",
	"It works on my air-gapped machine.",
	"CVE pending...",
	"The intern pushed to prod again.",
	"Don't worry, it's just a test environment.",
	"An idiot admires complexity.",
	"A genius admires simplicity.",
	"An idiot admires complexity and a genius admires simplicity.",
	"The best way to predict the future is to invent it.",
	"It wasn't DNS? Oh shit.",
	"Log a ticket on Jira.",
	"Did you log a ticket on Jira?",
	"Four day weeks, three day weekends.",
	"cat /etc/passwd | grep root",
}

func GetRandTitlePhrase() string {
	return titlePhrasesSlice[rand.Intn(len(titlePhrasesSlice))]
}