# beeper-imessage
A Matrix-iMessage puppeting bridge.

## Documentation
The bridge works like any other mautrix-go bridge, so the instructions at
<https://docs.mau.fi/bridges/go/setup.html> can be applied directly.
You can find precompiled binaries from the GitLab CI at
<https://mau.dev/mautrix/imessagego>.

Additionally, the bridge requires a registration provider running on a [Mac] or
[jailbroken iPhone], as well as a [relay server] to help the bridge and
registration provider connect to each other.

[Mac]: https://github.com/beeper/mac-registration-provider
[jailbroken iPhone]: https://github.com/beeper/phone-registration-provider
[relay server]: https://github.com/beeper/registration-relay

When connecting the bridge to your Beeper account with bbctl, you don't need to
self-host the relay, you only need to run the provider.

## Discussion
Matrix room: [#imessage:maunium.net](https://matrix.to/#/#imessage:maunium.net)
