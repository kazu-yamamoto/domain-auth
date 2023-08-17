{-# LANGUAGE OverloadedStrings #-}

module Network.DomainAuth.DKIM.Btag (
    removeBtagValue
  ) where

import Control.Applicative
import Control.Monad
import Data.Attoparsec.ByteString (Parser)
import qualified Data.Attoparsec.ByteString as P
import Data.ByteString as BS
import Data.ByteString.Builder (Builder)
import qualified Data.ByteString.Builder as B
import Data.ByteString.Char8 ()
import Data.Word8

-- |
--
-- >>> removeBtagValue "DKIM-Signature: a=rsa-sha256; d=example.net; s=brisbane;\n   c=simple; q=dns/txt; i=@eng.example.net;\n   t=1117574938; x=1118006938;\n   h=from:to:subject:date;\n   z=From:foo@eng.example.net|To:joe@example.com|\n     Subject:demo=20run|Date:July=205,=202005=203:44:08=20PM=20-0700;\n   bh=MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=;\n   b=dzdVyOfAKCdLXdJOc9G2q8LoXSlEniSbav+yuU4zGeeruD00lszZ\n            VoG4ZHRNiYzR;\n"
-- "DKIM-Signature: a=rsa-sha256; d=example.net; s=brisbane;\n   c=simple; q=dns/txt; i=@eng.example.net;\n   t=1117574938; x=1118006938;\n   h=from:to:subject:date;\n   z=From:foo@eng.example.net|To:joe@example.com|\n     Subject:demo=20run|Date:July=205,=202005=203:44:08=20PM=20-0700;\n   bh=MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=;\n   b=;\n"
removeBtagValue :: ByteString -> ByteString
removeBtagValue inp = case P.parseOnly remBtagValue inp of
  Left _   -> ""
  Right bs -> toStrict $ B.toLazyByteString bs

remBtagValue :: Parser Builder
remBtagValue = (<>) <$> inFix btag <*> anyString
  where
    anyString = B.byteString <$> P.takeWhile (const True)

inFix :: Parser Builder -> Parser Builder
inFix p = P.try p <|> (<>) <$> anyWord8 <*> inFix p
  where
    anyWord8 = B.word8 <$> P.anyWord8

btag :: Parser Builder
btag = do
    b <- B.word8 <$> P.word8 _b
    w <- B.byteString <$> P.takeWhile (P.inClass " \t\r\n")
    e <- B.word8 <$> P.word8 _equal
    void $ P.takeWhile1 (P.notInClass ";")
    s <- P.option mempty (B.word8 <$> P.word8 _semicolon)
    return (b <> w <> e <> s)

