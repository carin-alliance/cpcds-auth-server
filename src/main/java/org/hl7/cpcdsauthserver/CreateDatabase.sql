BEGIN TRANSACTION;

    CREATE TABLE IF NOT EXISTS Users (
        "username" varchar PRIMARY KEY,
        "patient_id" varchar NOT NULL,
        "password" varchar NOT NULL,
        "r" varchar NOT NULL,
        "refresh_token" varchar DEFAULT NULL,
        "timestamp" datetime DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS Clients (
        "id" varchar PRIMARY KEY,
        "secret" varchar NOT NULL,
        "timestamp" datetime DEFAULT CURRENT_TIMESTAMP
    );

COMMIT;