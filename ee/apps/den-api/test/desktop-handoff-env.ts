process.env.DATABASE_URL ??= "mysql://openwork:openwork@127.0.0.1:3306/openwork_test"
process.env.DEN_DB_ENCRYPTION_KEY ??= "x".repeat(32)
process.env.BETTER_AUTH_SECRET ??= "y".repeat(32)
process.env.BETTER_AUTH_URL ??= "http://127.0.0.1:8790"
process.env.CORS_ORIGINS ??= "https://app.openworklabs.com"
process.env.DEN_AUTH_ORIGIN ??= "https://app.openworklabs.com"
process.env.OPENWORK_DEV_MODE ??= "0"
