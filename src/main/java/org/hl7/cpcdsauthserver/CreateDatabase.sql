BEGIN TRANSACTION;

    CREATE TABLE IF NOT EXISTS Users (
        "username" varchar PRIMARY KEY,
        "id" varchar NOT NULL,
        "password" varchar NOT NULL,
        "r" varchar NOT NULL,
        "timestamp" datetime DEFAULT CURRENT_TIMESTAMP
    );

COMMIT;