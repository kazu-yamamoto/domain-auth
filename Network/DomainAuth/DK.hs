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
import qualified Network.DomainAuth.Pubkey.Base64 as B
import Network.DomainAuth.Pubkey.RSAPub
import Network.DomainAuth.Types

runDK :: Resolver -> Mail -> IO DAResult
runDK resolver mail = dk1
  where
    dk1     = maybe (return DANone)      dk2 $ lookupField dkFieldKey (mailHeader mail)
    dk2 dkv = maybe (return DAPermError) dk3 $ parseDK (toRaw dkv)
    dk3     = runDK' resolver mail

runDK' :: Resolver -> Mail -> DK -> IO DAResult
runDK' resolver mail dk = maybe DATempError (verify sig cmail) <$> pub
  where
    pub = lookupPublicKey resolver dom
    dom = dkSelector dk ++ "._domainkey." ++ dkDomain dk
    sig = B.decode (dkSignature dk)
    cmail = prepareDK dk mail
    verify s c p = if verifyDK p s c then DAPass else DAFail
