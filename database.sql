START TRANSACTION;

CREATE TABLE IF NOT EXISTS ACCOUNT (
	ID SERIAL PRIMARY KEY,
	NAME VARCHAR(24) NOT NULL UNIQUE,
	EMAIL VARCHAR(128) NOT NULL UNIQUE,
	EMAIL_VERIFIED BOOLEAN NOT NULL DEFAULT FALSE,
	PASSWORD BYTEA NOT NULL,
	REGISTRATION_DATE TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	SKIN SMALLINT NOT NULL,
	SEX BOOLEAN NOT NULL,
	MONEY INT NOT NULL DEFAULT 0,
	XP INT NOT NULL DEFAULT 0,
	LEVEL SMALLINT NOT NULL DEFAULT 1,

	HEALTH FLOAT NOT NULL DEFAULT 0.0,
	ARMOR FLOAT NOT NULL DEFAULT 0.0,
	HUNGER FLOAT NOT NULL DEFAULT 0.0,
	THIRST FLOAT NOT NULL DEFAULT 0.0,

	POS_X FLOAT NOT NULL,
	POS_Y FLOAT NOT NULL,
	POS_Z FLOAT NOT NULL,
	ANGLE FLOAT NOT NULL,
	VIRTUAL_WORLD INT NOT NULL DEFAULT 0,
	INTERIOR SMALLINT NOT NULL DEFAULT 0,

	ADMIN_LEVEL SMALLINT NOT NULL DEFAULT 0,

	CURRENT_PLAYERID SMALLINT NOT NULL DEFAULT -1,
	CURRENT_CONNECTION INTEGER NOT NULL DEFAULT 0,
	PLAYED_TIME INTEGER NOT NULL DEFAULT 0,
	CONFIG_BITS BIT VARYING DEFAULT B'0',

	VIP_LEVEL SMALLINT NOT NULL DEFAULT 0,
	VIP_EXPIRACY TIMESTAMP DEFAULT NULL,

	MUTED_TIME INTEGER NOT NULL DEFAULT 0,
	WANTED_LEVEL SMALLINT NOT NULL DEFAULT 0,
	JAIL_TIME INTEGER NOT NULL DEFAULT 0
);

UPDATE ACCOUNT SET CURRENT_CONNECTION = 0, CURRENT_PLAYERID = -1;

CREATE TABLE IF NOT EXISTS CONNECTION_LOG (
	ACCOUNT_ID SERIAL NOT NULL,
	IP_ADDRESS VARCHAR(16) NOT NULL,
	DATE TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

	FOREIGN KEY(ACCOUNT_ID) REFERENCES ACCOUNT(ID) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS BANS (
	BANNED_USER VARCHAR(24) NOT NULL UNIQUE,
	BANNED_IP VARCHAR(16) DEFAULT NULL,
	ADMIN_ID INT DEFAULT NULL,
	REASON TEXT NOT NULL DEFAULT 'No especificada',
	ISSUED_DATE TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	EXPIRATION_DATE TIMESTAMP DEFAULT NULL
);

COMMIT;