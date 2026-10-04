package pubsub

// PubSub interface for scalable message distribution. A message on a channel
// reaches every callback subscribed to it; Unsubscribe removes them all.
type PubSub interface {
	Publish(channel string, message []byte) error
	Subscribe(channel string, callback func(message []byte)) error
	Unsubscribe(channel string) error
}

// GapReporter is implemented by a PubSub that delivers at most once. fn runs
// after every interruption during which messages may have been lost, once
// delivery has resumed: a subscriber that reads current state from its store
// then has everything, since whatever changes next is delivered again.
type GapReporter interface {
	OnGap(fn func())
}
