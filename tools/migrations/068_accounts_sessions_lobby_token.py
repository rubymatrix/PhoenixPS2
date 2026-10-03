import mariadb


def migration_name():
    return "Adding lobby_token to accounts_sessions"


def check_preconditions(cur):
    return


def needs_to_run(cur):
    cur.execute("SHOW COLUMNS FROM accounts_sessions LIKE 'lobby_token'")
    if not cur.fetchone():
        return True
    return False


def migrate(cur, db):
    try:
        cur.execute("ALTER TABLE accounts_sessions \
                ADD COLUMN IF NOT EXISTS `lobby_token` char(64) NOT NULL DEFAULT '' AFTER `client_expansions`;")
        db.commit()
    except mariadb.Error as err:
        print("Something went wrong: {}".format(err))
