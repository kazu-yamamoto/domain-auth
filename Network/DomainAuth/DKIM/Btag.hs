module Network.DomainAuth.DKIM.Btag (
    removeBtagValue
  ) where

import Control.Monad
import Data.ByteString.Char8
import Data.Maybe
import Text.Appar.ByteString

-- |
--
-- >>> removeBtagValue "DKIM-Signature: a=rsa-sha256; d=example.net; s=brisbane;\n   c=simple; q=dns/txt; i=@eng.example.net;\n   t=1117574938; x=1118006938;\n   h=from:to:subject:date;\n   z=From:foo@eng.example.net|To:joe@example.com|\n     Subject:demo=20run|Date:July=205,=202005=203:44:08=20PM=20-0700;\n   bh=MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=;\n   b=dzdVyOfAKCdLXdJOc9G2q8LoXSlEniSbav+yuU4zGeeruD00lszZ\n            VoG4ZHRNiYzR;\n"
-- "DKIM-Signature: a=rsa-sha256; d=example.net; s=brisbane;\n   c=simple; q=dns/txt; i=@eng.example.net;\n   t=1117574938; x=1118006938;\n   h=from:to:subject:date;\n   z=From:foo@eng.example.net|To:joe@example.com|\n     Subject:demo=20run|Date:July=205,=202005=203:44:08=20PM=20-0700;\n   bh=MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=;\n   b=;\n"
removeBtagValue :: ByteString -> ByteString
removeBtagValue = pack . fromMaybe "" . parse remBtagValue

remBtagValue :: Parser String
remBtagValue = (++) <$> inFix btag <*> many anyChar

inFix :: Parser String -> Parser String
inFix p = try p <|> (:) <$> anyChar <*> inFix p

btag :: Parser String
btag = do
    b <- string "b"
    w <- many $ oneOf " \t\r\n"
    e <- string "="
    void . some $ noneOf ";"
    s <- option "" (string ";")
    return $ b ++ w ++ e ++ s
