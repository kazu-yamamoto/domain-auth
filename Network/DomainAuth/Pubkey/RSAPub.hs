module Network.DomainAuth.Pubkey.RSAPub where

import Codec.Crypto.RSA
import Control.Applicative
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString.Lazy.Char8 as LC (pack)
import Network.DNS (Domain)
import qualified Network.DNS as DNS hiding (Domain)
import Network.DomainAuth.Mail
import qualified Network.DomainAuth.Pubkey.Base64 as B
import qualified Network.DomainAuth.Pubkey.Der as D

lookupPublicKey :: DNS.Resolver -> Domain -> IO (Maybe PublicKey)
lookupPublicKey resolver domain = decode <$> lookupPublicKey' resolver domain
  where
    decode = (>>= return . decodeRSAPublicyKey)

lookupPublicKey' :: DNS.Resolver -> String -> IO (Maybe L.ByteString)
lookupPublicKey' resolver domain = extractPub <$> DNS.lookupTXT resolver domain

extractPub :: Maybe [L.ByteString] -> Maybe L.ByteString
extractPub = (>>= lookup (LC.pack "p") . parseTaggedValue . head)

decodeRSAPublicyKey :: L.ByteString -> PublicKey
decodeRSAPublicyKey bs = PublicKey size n e
  where
    subjectPublicKeyInfo = D.decode . B.decode $ bs
    [_, subjectPublicKey] = D.tlv subjectPublicKeyInfo
    rsaPublicKey = D.decode . bitString . D.cnt $ subjectPublicKey
    [bn',be'] = D.tlv rsaPublicKey
    bn = L.dropWhile (== 0) $ D.cnt bn'
    be = D.cnt be'
    n = toNum bn
    e = toNum be
    size = fromIntegral . L.length $ bn
    toNum = L.foldl' (\x y -> x*256 + fromIntegral y) 0
    bitString = L.tail
