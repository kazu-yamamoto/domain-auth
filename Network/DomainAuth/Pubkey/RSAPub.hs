{-# LANGUAGE OverloadedStrings #-}

module Network.DomainAuth.Pubkey.RSAPub where

import Codec.Crypto.RSA
import Control.Applicative
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS (foldl', dropWhile, length, tail)
import qualified Data.ByteString.Char8 as BS ()
import Network.DNS (Domain)
import qualified Network.DNS as DNS hiding (Domain)
import Network.DomainAuth.Mail
import qualified Network.DomainAuth.Pubkey.Base64 as B
import qualified Network.DomainAuth.Pubkey.Der as D

lookupPublicKey :: DNS.Resolver -> Domain -> IO (Maybe PublicKey)
lookupPublicKey resolver domain = decode <$> lookupPublicKey' resolver domain
  where
    decode = (>>= return . decodeRSAPublicyKey)

lookupPublicKey' :: DNS.Resolver -> Domain -> IO (Maybe ByteString)
lookupPublicKey' resolver domain = extractPub <$> DNS.lookupTXT resolver domain

extractPub :: Maybe [ByteString] -> Maybe ByteString
extractPub = (>>= lookup "p" . parseTaggedValue . head)

decodeRSAPublicyKey :: ByteString -> PublicKey
decodeRSAPublicyKey bs = PublicKey size n e
  where
    subjectPublicKeyInfo = D.decode . B.decode $ bs
    [_, subjectPublicKey] = D.tlv subjectPublicKeyInfo
    rsaPublicKey = D.decode . bitString . D.cnt $ subjectPublicKey
    [bn',be'] = D.tlv rsaPublicKey
    bn = BS.dropWhile (== 0) $ D.cnt bn'
    be = D.cnt be'
    n = toNum bn
    e = toNum be
    size = fromIntegral . BS.length $ bn
    toNum = BS.foldl' (\x y -> x*256 + fromIntegral y) 0
    bitString = BS.tail
