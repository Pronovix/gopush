SET NAMES utf8;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
--  Table structure for `APIToken`
-- ----------------------------
DROP TABLE IF EXISTS `APIToken`;
CREATE TABLE `APIToken` (
  `Mail` varchar(255) NOT NULL,
  `PublicKey` text NOT NULL,
  `Admin` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`Mail`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

SET FOREIGN_KEY_CHECKS = 1;
