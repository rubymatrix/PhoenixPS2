-- [Phoenix] Federated accounts
-- Maps a player's global id from a PlayOnline provider (xitoken: <provider server id>:<subject>) to the account
-- that owns their characters on this world. The federation gateway in xi_world admits a world-entry token only for
-- a character whose account is mapped to the token's player here (see src/world/federation_gateway.cpp).
--
-- Rows are written by whoever creates the account for the player: today the Crystal lobby, when it makes the
-- LSB shadow account for a POL member.
CREATE TABLE IF NOT EXISTS `accounts_federated` (
  `provider` CHAR(26) NOT NULL,
  `subject` VARCHAR(128) NOT NULL,
  `accid` INT UNSIGNED NOT NULL,
  `created` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`provider`, `subject`),
  UNIQUE KEY `uq_accid` (`accid`),
  CONSTRAINT `fk_federated_accid` FOREIGN KEY (`accid`) REFERENCES `accounts`(`id`) ON DELETE CASCADE
);
