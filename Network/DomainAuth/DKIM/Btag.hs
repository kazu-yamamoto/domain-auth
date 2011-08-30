module Network.DomainAuth.DKIM.Btag where

import Data.ByteString.Char8
import Data.Maybe
import Text.Appar.ByteString

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
    some $ noneOf ";"
    s <- option "" (string ";")
    return $ b ++ w ++ e ++ s
