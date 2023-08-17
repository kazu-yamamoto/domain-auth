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
-- >>> withResolver rs $ \rslv -> lookupPublicKey rslv "20221208._domainkey.gmail.com"
-- Just (PublicKey {public_size = 256, public_n = 22678151869562939359899136428859256198402569240680475393086048829021713182010490409724483359945551283969506235489826762257419985891230334120904178414351809046671461143996599803281758436654811035615578092428632166371331342907633917876752170113620966009358291594609542956251740141784694619901495773614035042135465203364073740861194611021551592336450807473519143746970021740067888325723330796836146546417386918505126721680365151889317110944800331756379997471380657912089911948147086686452887197011845657708078311037666769039161141500897109834073427400667740315220146696437513966171590587213846521825862509466370365529359, public_e = 65537})
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
    pub = case decodeASN1' (undefined :: DER) der of
      Left _     -> error "decodeRSAPublicyKey (1)"
      Right ans1 -> case fromASN1 ans1 of
        Right (PubKeyRSA p,[]) -> p
        _                      -> error "decodeRSAPublicyKey (2)"
