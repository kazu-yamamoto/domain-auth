{-# LANGUAGE OverloadedStrings #-}

module Network.DomainAuth.PRD.Domain (
    extractDomain
  ) where

import Network.DNS (Domain)
import Network.DomainAuth.Mail
import Network.DomainAuth.PRD.Lexer
import qualified Data.Attoparsec.ByteString as P
import qualified Data.ByteString.Char8 as BS

-- | Extract a domain from a value of a header field.
--
-- >>> extractDomain "Alice Brown <alice.brown@example.com>"
-- Just "example.com"
-- >>> extractDomain "\"Alice . Brown\" <alice.brown@example.com> (Nickname here)"
-- Just "example.com"
-- >>> extractDomain "alice.brown@example.com"
-- Just "example.com"
-- >>> extractDomain "Alice Brown <example.com>"
-- Nothing

extractDomain :: RawFieldValue -> Maybe Domain
extractDomain bs = case P.parseOnly structured bs of
  Left _   -> Nothing
  Right st -> takeDomain st
    where
      takeDomain = dropTail . dropWhile (/="@")
      dropTail [] = Nothing
      dropTail xs = (Just . BS.concat . takeWhile (/=">") . tail) xs
