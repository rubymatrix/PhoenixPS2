-- [Phoenix] Federation replay guard
-- Ids of xitoken tokens the federation gateway has accepted, kept until they expire, so each token is used once
-- even with several processes. Expired rows are deleted by the gateway as it goes.
CREATE TABLE IF NOT EXISTS `federation_used_tokens` (
  `issuer` CHAR(26) NOT NULL,
  `jti` VARCHAR(64) NOT NULL,
  `expires` DATETIME NOT NULL,
  PRIMARY KEY (`issuer`, `jti`),
  INDEX `idx_expires` (`expires`)
);
