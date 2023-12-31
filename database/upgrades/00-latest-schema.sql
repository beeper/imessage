-- v0 -> v23 (compatible with v11+): Latest schema

CREATE TABLE "user" (
	-- only: postgres
	rowid BIGINT  PRIMARY KEY GENERATED BY DEFAULT AS IDENTITY,
	-- only: sqlite
	rowid INTEGER PRIMARY KEY,

	mxid               TEXT NOT NULL UNIQUE,
	access_token       TEXT NOT NULL,
	space_room         TEXT NOT NULL,
	management_room    TEXT NOT NULL,

	hide_read_receipts BOOLEAN NOT NULL,

	apple_registration           jsonb,
	secondary_apple_registration jsonb,

	fcm_push_token TEXT NOT NULL,

	registered_phone_numbers jsonb
);

CREATE TABLE portal (
	uri                TEXT    NOT NULL,
	receiver           BIGINT  NOT NULL,
	service            TEXT    NOT NULL,
	group_id           TEXT    NOT NULL,
	participants       jsonb   NOT NULL,
	outgoing_handle    TEXT    NOT NULL,
	mxid               TEXT             UNIQUE,
	name               TEXT    NOT NULL,
	name_set           BOOLEAN NOT NULL DEFAULT false,
	avatar_hash        bytea,
	avatar_guid        TEXT,
	avatar_url         TEXT    NOT NULL,
	avatar_set         BOOLEAN NOT NULL DEFAULT false,
	encrypted          BOOLEAN NOT NULL,
	in_space           BOOLEAN NOT NULL,
	properties_version INTEGER NOT NULL DEFAULT 0,

	PRIMARY KEY (uri, receiver),
	CONSTRAINT portal_user_fkey FOREIGN KEY (receiver) REFERENCES "user"(rowid) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE puppet (
	uri              TEXT    NOT NULL,
	receiver         BIGINT  NOT NULL,
	displayname      TEXT    NOT NULL,
	avatar_hash      bytea,
	avatar_url       TEXT    NOT NULL,
	contact_info_set BOOLEAN NOT NULL DEFAULT false,

	PRIMARY KEY (uri, receiver),
	CONSTRAINT portal_user_fkey FOREIGN KEY (receiver) REFERENCES "user"(rowid) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE message (
	portal_uri       TEXT    NOT NULL,
	portal_receiver  BIGINT  NOT NULL,
	id               uuid    NOT NULL,
	part             INTEGER NOT NULL,
	start_index      INTEGER NOT NULL,
	length           INTEGER NOT NULL,
	mxid             TEXT    NOT NULL UNIQUE,
	mx_room          TEXT    NOT NULL,
	sender_uri       TEXT    NOT NULL,
	timestamp        BIGINT  NOT NULL,
	receiving_handle TEXT    NOT NULL,
	reply_to_id 	 uuid,
	reply_to_part    INTEGER,

	PRIMARY KEY (portal_uri, portal_receiver, id, part),
	CONSTRAINT message_portal_fkey FOREIGN KEY (portal_uri, portal_receiver) REFERENCES portal(uri, receiver)
	    ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE tapback (
	portal_uri       TEXT    NOT NULL,
	portal_receiver  BIGINT  NOT NULL,
	message_id       uuid    NOT NULL,
	message_part     INTEGER NOT NULL,
	sender_uri       TEXT    NOT NULL,
	type             INTEGER NOT NULL,
	id               uuid    NOT NULL,
	mxid             TEXT    NOT NULL UNIQUE,
	receiving_handle TEXT    NOT NULL,

	PRIMARY KEY (portal_uri, portal_receiver, message_id, message_part, sender_uri),
	CONSTRAINT tapback_message_fkey FOREIGN KEY (portal_uri, portal_receiver, message_id, message_part)
	    REFERENCES message(portal_uri, portal_receiver, id, part) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE ids_cache (
	user_id     BIGINT  NOT NULL,
	our_uri     TEXT    NOT NULL,
	their_uri   TEXT    NOT NULL,
	timestamp   BIGINT  NOT NULL,
	result      jsonb   NOT NULL,
	broadcasted BOOLEAN NOT NULL,

	PRIMARY KEY (user_id, our_uri, their_uri),
	CONSTRAINT ids_cache_user_fkey FOREIGN KEY (user_id) REFERENCES "user"(rowid) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE kv_store (
	key   TEXT NOT NULL PRIMARY KEY,
	value TEXT NOT NULL
);

CREATE TABLE outgoing_counter (
	user_id   BIGINT NOT NULL,
	their_uri TEXT NOT NULL,
	counter   BIGINT NOT NULL,

	PRIMARY KEY (user_id, their_uri),
	CONSTRAINT outgoing_counter_user_fkey FOREIGN KEY (user_id)
		REFERENCES "user"(rowid) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE file_transfer (
	user_id    BIGINT  NOT NULL,
	identifier TEXT    NOT NULL,
	mxc_uri    TEXT    NOT NULL,
	temp_path  TEXT    NOT NULL,
	error      TEXT    NOT NULL,
	state      jsonb   NOT NULL,

	PRIMARY KEY (user_id, identifier)
);

CREATE TABLE reroute_history (
	user_id    BIGINT NOT NULL,
	handle     TEXT   NOT NULL,
	timestamp  BIGINT NOT NULL,

	PRIMARY KEY (user_id, handle)
);
