module github.com/PinkNoize/discord-server-manager/server-manager

go 1.16

require (
	cloud.google.com/go/firestore v1.6.1
	cloud.google.com/go/secretmanager v1.3.0 // indirect
	github.com/bwmarrin/discordgo v0.24.0 // indirect
	github.com/google/uuid v1.3.0
	github.com/sony/sonyflake v1.0.0 // indirect
	google.golang.org/api v0.70.0
	google.golang.org/grpc v1.44.0
	github.com/PinkNoize/discord-server-manager/server-manager-utils v0.0.0
)

replace (
   github.com/PinkNoize/discord-server-manager/server-manager-utils => ../server-manager-utils
)
