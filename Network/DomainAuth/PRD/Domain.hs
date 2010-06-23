module Network.DomainAuth.PRD.Domain (extractDomain) where

import Network.DNS (Domain)
import Network.DomainAuth.Mail
import Network.DomainAuth.PRD.Lexer
import Text.Appar.LazyByteString

{-|
  Extract a domain from a value of a header field.
-}

extractDomain :: FieldValue -> Maybe Domain
extractDomain bs = parse structured bs >>= takeDomain
    where
      takeDomain = dropTail . dropWhile (/="@")
      dropTail [] = Nothing
      dropTail xs = (Just . concat . takeWhile (/=">") . tail) xs
