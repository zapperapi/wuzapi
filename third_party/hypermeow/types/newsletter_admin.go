package types

import "time"

// NewsletterFollower is a follower of a channel, as listed to its admins.
type NewsletterFollower struct {
	// ID is the LID of the follower.
	ID          JID
	DisplayName string
	// PhoneNumber is empty when WhatsApp does not show the number to the admin.
	PhoneNumber JID
	Username    string
	Role        NewsletterRole
	FollowTime  time.Time
}

// NewsletterPinnedMessage is a pinned message of a channel.
type NewsletterPinnedMessage struct {
	ServerID   MessageServerID
	Expiration time.Time
}

// NewsletterInsights holds the audience metrics of a channel.
type NewsletterInsights struct {
	// Status is the state of the metrics, as WhatsApp reports it (for example "MISSING").
	Status     string
	LastUpdate time.Time
	Metrics    []NewsletterInsightResult
}

// NewsletterInsightResult holds the values of one requested metric.
type NewsletterInsightResult struct {
	// ID is the id given in the request.
	ID     int
	Values []NewsletterInsightValue
}

// NewsletterInsightValue is one value of a metric. Country, Role and Timestamp
// are set only when the metric is grouped by them.
type NewsletterInsightValue struct {
	Value     float64
	Country   string
	Role      string
	Timestamp time.Time
}
