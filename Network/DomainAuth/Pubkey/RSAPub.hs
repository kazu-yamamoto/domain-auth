{-# LANGUAGE OverloadedStrings #-}

module Network.DomainAuth.Pubkey.RSAPub (
    lookupPublicKey
  ) where

import Crypto.PubKey.RSA (PublicKey)
import Data.ASN1.BinaryEncoding (DER)
import Data.ASN1.Encoding (decodeASN1')
import Data.ASN1.Types (fromASN1)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as BS ()
import Data.X509 (PubKey(PubKeyRSA))
import Network.DNS (Domain)
import qualified Network.DNS as DNS
import Network.DomainAuth.Mail
import qualified Network.DomainAuth.Pubkey.Base64 as B

-- $setup
-- >>> import Network.DNS

-- | Looking up an RSA public key
--
-- >>> rs <- DNS.makeResolvSeed DNS.defaultResolvConf
-- >>> withResolver rs $ \rslv -> lookupPublicKey rslv "dk200510._domainkey.yahoo.co.jp"
-- Just (PublicKey {public_size = 128, public_n = 124495277115430906234131617223399742059624761592171426860362133400468320289284068350453787798555522712914036293436636386707903510390018044090096883314714401752103035965668114514933570840775088208966674120428191313530595210688523478828022953238411688594634270571841869051696953556782155414877029327479844990933, public_e = 65537})
-- >>> withResolver rs $ \rslv -> lookupPublicKey rslv "20161025._domainkey.gmail.com"
-- Just (PublicKey {public_size = 256, public_n = 24002918530496096406691035681124918576525139397315303508411989678485471042094243709057313703002506577481962009015943359911855470236184740304869372300375695346466126498491672986773463137306714366250125164042667360646066116764211863426455899157774209331432246892273100824803003088472583507901403747123280231573655315087668569169140244507741538460717772392364103610973022227332742456151275783849571119048507254523999452581754451573432729267867937880516609319975372273089173378196646435625090021348583100824870283641053888848697729241628460935831026221013673635926904278136940569963717548356154570137751386534390787055991, public_e = 65537})
lookupPublicKey :: DNS.Resolver -> Domain -> IO (Maybe PublicKey)
lookupPublicKey resolver domain = do
    mpub <- lookupPublicKey' resolver domain
    return $ case mpub of
      Nothing  -> Nothing
      Just pub -> Just $ decodeRSAPublicyKey pub

lookupPublicKey' :: DNS.Resolver -> Domain -> IO (Maybe ByteString)
lookupPublicKey' resolver domain = do
    ex <- DNS.lookupTXT resolver domain
    case ex of
        Left  _ -> return Nothing
        Right x -> return $ extractPub x

extractPub :: [ByteString] -> Maybe ByteString
extractPub = lookup "p" . parseTaggedValue . head

decodeRSAPublicyKey :: ByteString -> PublicKey
decodeRSAPublicyKey b64 = pub
  where
    der = B.decode b64
    Right ans1 = decodeASN1' (undefined :: DER) der
    Right (PubKeyRSA pub,[]) = fromASN1 ans1
