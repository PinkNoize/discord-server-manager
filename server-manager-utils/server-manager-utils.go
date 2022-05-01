package server_manager_utils

type ForwardPubSub struct {
	Command     string  `json:"command"`
	Interaction *[]byte `json:"interaction,omitempty"`
}
