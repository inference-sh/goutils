package pubsub

// PubSub interface for scalable message distribution
type PubSub interface {
	Publish(channel string, message []byte) error
	Subscribe(channel string, callback func(message []byte)) error
	Unsubscribe(channel string) error
}
