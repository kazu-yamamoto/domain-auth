{-# LANGUAGE OverloadedStrings #-}

module Network.DomainAuth.DKIM.Btag (
    removeBtagValue
  ) where

import Control.Applicative
import Control.Monad
import Data.Attoparsec.ByteString (Parser)
import qualified Data.Attoparsec.ByteString as P
import qualified Data.Attoparsec.Combinator as P (option)
import Data.ByteString as BS
import Data.ByteString.Char8 ()

-- |
--
-- >>> removeBtagValue "DKIM-Signature: a=rsa-sha256; d=example.net; s=brisbane;\n   c=simple; q=dns/txt; i=@eng.example.net;\n   t=1117574938; x=1118006938;\n   h=from:to:subject:date;\n   z=From:foo@eng.example.net|To:joe@example.com|\n     Subject:demo=20run|Date:July=205,=202005=203:44:08=20PM=20-0700;\n   bh=MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=;\n   b=dzdVyOfAKCdLXdJOc9G2q8LoXSlEniSbav+yuU4zGeeruD00lszZ\n            VoG4ZHRNiYzR;\n"
-- "DKIM-Signature: a=rsa-sha256; d=example.net; s=brisbane;\n   c=simple; q=dns/txt; i=@eng.example.net;\n   t=1117574938; x=1118006938;\n   h=from:to:subject:date;\n   z=From:foo@eng.example.net|To:joe@example.com|\n     Subject:demo=20run|Date:July=205,=202005=203:44:08=20PM=20-0700;\n   bh=MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=;\n   b=;\n"
removeBtagValue :: ByteString -> ByteString
removeBtagValue inp = case P.parseOnly remBtagValue inp of
  Left _   -> ""
  Right bs -> bs

remBtagValue :: Parser ByteString
remBtagValue = BS.append <$> inFix btag <*> P.takeWhile (const True)

inFix :: Parser ByteString -> Parser ByteString
inFix p = P.try p <|> BS.cons <$> P.anyWord8 <*> inFix p

btag :: Parser ByteString
btag = do
    b <- P.string "b"
    w <- P.takeWhile (P.inClass " \t\r\n")
    e <- P.string "="
    void $ P.takeWhile1 (P.notInClass ";")
    s <- P.option "" (P.string ";")
    return $ BS.concat [b,w,e,s]
