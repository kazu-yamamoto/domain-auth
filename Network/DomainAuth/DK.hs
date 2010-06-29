module Network.DomainAuth.DK (
    dkFieldKey, parseDK
  , DK, dkDomain, dkSelector
  , runDK, runDK'
  ) where

import Control.Applicative
import Network.DNS as DNS (Resolver)
import Network.DomainAuth.DK.Parser
import Network.DomainAuth.DK.Types
import Network.DomainAuth.DK.Verify
import Network.DomainAuth.Mail
import Network.DomainAuth.Pubkey.RSAPub
import Network.DomainAuth.Types

runDK :: Resolver -> Mail -> IO DAResult
runDK resolver mail = dk1
  where
    dk1     = maybe (return DANone)      dk2 $ lookupField dkFieldKey (mailHeader mail)
    dk2 dkv = maybe (return DAPermError) dk3 $ parseDK (toRaw dkv)
    dk3     = runDK' resolver mail

runDK' :: Resolver -> Mail -> DK -> IO DAResult
runDK' resolver mail dk = maybe DATempError (verify mail dk) <$> pub
  where
    pub = lookupPublicKey resolver dom
    dom = dkSelector dk ++ "._domainkey." ++ dkDomain dk
    verify m d p = if verifyDK m d p then DAPass else DAFail
