module github.com/beeper/imessage

go 1.21

require (
	github.com/emersion/go-vcard v0.0.0-20230815062825-8fda7d206ec9
	github.com/gabriel-vasile/mimetype v1.4.3
	github.com/google/uuid v1.5.0
	github.com/gorilla/mux v1.8.0
	github.com/mattn/go-sqlite3 v1.14.19
	github.com/nyaruka/phonenumbers v1.3.0
	github.com/rs/zerolog v1.31.0
	github.com/stretchr/testify v1.8.4
	github.com/strukturag/libheif v1.17.6
	github.com/tidwall/gjson v1.17.0
	go.mau.fi/util v0.2.2-0.20231120145840-55dca048d0d9
	go.mau.fi/zeroconfig v0.1.2
	go4.org v0.0.0-20230225012048-214862532bf5
	golang.org/x/crypto v0.17.0
	golang.org/x/exp v0.0.0-20231219180239-dc181d75b848
	golang.org/x/image v0.14.0
	golang.org/x/net v0.19.0
	golang.org/x/sys v0.15.0
	golang.org/x/time v0.5.0
	google.golang.org/protobuf v1.31.0
	howett.net/plist v1.0.1
	maunium.net/go/maulogger/v2 v2.4.1
	maunium.net/go/mautrix v0.16.3-0.20231117160133-4784d6d09fe2
)

require (
	github.com/coreos/go-systemd/v22 v22.5.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/gorilla/websocket v1.5.0 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/lib/pq v1.10.9 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.19 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.0 // indirect
	github.com/tidwall/sjson v1.2.5 // indirect
	github.com/yuin/goldmark v1.6.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.2.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	maunium.net/go/mauflag v1.0.0 // indirect
)

// we only need heif from go4.org, so make sure other bloat can't be included
exclude (
	cloud.google.com/go v0.53.0
	cloud.google.com/go/storage v1.5.0
	golang.org/x/oauth2 v0.0.0-20200107190931-bf48bf16ab8d
	google.golang.org/api v0.17.0
)
