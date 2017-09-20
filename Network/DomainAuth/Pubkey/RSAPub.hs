{-# LANGUAGE OverloadedStrings #-}

module Network.DomainAuth.Pubkey.RSAPub where

import Crypto.PubKey.RSA
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS (foldl', dropWhile, length, tail)
import qualified Data.ByteString.Char8 as BS ()
import qualified Data.ByteString.Lazy as BL
import Network.DNS (Domain)
import qualified Network.DNS as DNS hiding (Domain)
import Network.DomainAuth.Mail
import qualified Network.DomainAuth.Pubkey.Base64 as B
import qualified Network.DomainAuth.Pubkey.Der as D

-- $setup
-- >>> import Network.DNS

lookupPublicKey :: DNS.Resolver -> Domain -> IO (Maybe PublicKey)
lookupPublicKey resolver domain = decode <$> lookupPublicKey' resolver domain
  where
    decode = (>>= return . decodeRSAPublicyKey)

-- |
--
-- >>> rs <- DNS.makeResolvSeed DNS.defaultResolvConf
-- >>> withResolver rs $ \rslv -> lookupPublicKey' rslv "dk200510._domainkey.yahoo.co.jp"
-- Just "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCxSYNH3flPtGnDPuCKsuZ1VJD/sToRfS38qMT/YrOvTguUABLeMGheCTg7S3HGas+JEOcxEsYuOPxYULGogqzJ8WKpwlh4Gdz+fcaPstKcsUZvurAfLmudvLtYtabuaHyUH586GzAW7WWf80rvVR58NlFf+n8tyGZvlc6MpaVv1QIDAQAB"
-- >>> withResolver rs $ \rslv -> lookupPublicKey' rslv "20161025._domainkey.gmail.com"
-- Just "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAviPGBk4ZB64UfSqWyAicdR7lodhytae+EYRQVtKDhM+1mXjEqRtP/pDT3sBhazkmA48n2k5NJUyMEoO8nc2r6sUA+/Dom5jRBZp6qDKJOwjJ5R/OpHamlRG+YRJQqR\222tqEgSiJWG7h7efGYWmh4URhFM9k9+rmG/CwCgwx7Et+c8OMlngaLl04/bPmfpjdEyLWyNimk761CX6KymzYiRDNz1MOJOJ7OzFaS4PFbVLn0m5mf0HVNtBpPwWuCNvaFVflUYxEyblbB6h/oWOPGbzoSgtRA47SHV53SwZjIsVpbq4LxUW9IxAEwYzGcSgZ4n5Q8X8TndowsDUzoccPFGhdwIDAQAB"
lookupPublicKey' :: DNS.Resolver -> Domain -> IO (Maybe ByteString)
lookupPublicKey' resolver domain = do
    ex <- DNS.lookupTXT resolver domain
    case ex of
        Left  _ -> return Nothing
        Right x -> return $ extractPub x

extractPub :: [ByteString] -> Maybe ByteString
extractPub = lookup "p" . parseTaggedValue . head

decodeRSAPublicyKey :: ByteString -> PublicKey
decodeRSAPublicyKey bs = PublicKey size n e
  where
    subjectPublicKeyInfo = D.decode . B.decode $ bs
    [_, subjectPublicKey] = D.tlv subjectPublicKeyInfo
    rsaPublicKey = D.decode . toLazy . bitString . D.cnt $ subjectPublicKey
    [bn',be'] = D.tlv rsaPublicKey
    bn = BS.dropWhile (== 0) $ D.cnt bn'
    be = D.cnt be'
    n = toNum bn
    e = toNum be
    size = fromIntegral . BS.length $ bn
    toNum = BS.foldl' (\x y -> x*256 + fromIntegral y) 0
    bitString = BS.tail
    toLazy x = BL.fromChunks [x]
