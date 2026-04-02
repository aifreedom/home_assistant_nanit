package app

import (
	"github.com/indiefan/home_assistant_nanit/pkg/mqtt"
	"time"
)

// Opts - application run options
type Opts struct {
	NanitCredentials NanitCredentials
	SessionFile      string
	DataDirectories  DataDirectories
	HTTPEnabled      bool
	MQTT             *mqtt.Opts
	RTMP             *RTMPOpts
	EventPolling     EventPollingOpts
}

// NanitCredentials - user credentials for Nanit account
type NanitCredentials struct {
	Email        string
	Password     string
	RefreshToken string
}

// DataDirectories - dictionary of dir paths
type DataDirectories struct {
	BaseDir  string
	VideoDir string
	LogDir   string
}

// RTMPOpts - options for RTMP streaming
type RTMPOpts struct {
	// IP:Port of the interface on which we should listen for the camera (publisher)
	ListenAddr string

	// IP:Port under which can Cam reach the RTMP server
	PublicAddr string

	// IP:Port on which to listen for subscriber (client) connections.
	// If empty, subscribers connect on the same port as the publisher.
	SubscriberListenAddr string
}

type EventPollingOpts struct {
	Enabled         bool
	PollingInterval time.Duration
	MessageTimeout  time.Duration
}
