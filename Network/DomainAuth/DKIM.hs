module Network.DomainAuth.DKIM (
    dkimFieldKey, parseDKIM
  , DKIM, dkimDomain, dkimSelector
  , runDKIM, runDKIM'
  ) where

import Control.Applicative
import Network.DNS as DNS (Resolver)
import Network.DomainAuth.DKIM.Parser
import Network.DomainAuth.DKIM.Types
import Network.DomainAuth.DKIM.Verify
import Network.DomainAuth.Mail
import qualified Network.DomainAuth.Pubkey.Base64 as B
import Network.DomainAuth.Pubkey.RSAPub
import Network.DomainAuth.Types

runDKIM :: Resolver -> Mail -> IO DAResult
runDKIM resolver mail = dkim1
  where
    dkim1     = maybe (return DANone)      dkim2 $ lookupField dkimFieldKey mail
    dkim2 rdkim = maybe (return DAPermError) dkim3 $ parseDKIM rdkim
    dkim3     = runDKIM' resolver mail

runDKIM' :: Resolver -> Mail -> DKIM -> IO DAResult
runDKIM' resolver mail dkim = maybe DATempError (verify sig cmail) <$> pub
  where
    pub = lookupPublicKey resolver dom
    dom = dkimSelector dkim ++ "._domainkey." ++ dkimDomain dkim
    sig = B.decode (dkimSignature dkim)
    cmail = prepareDKIM dkim mail
    verify s c p = if verifyDKIM p s c then DAPass else DAFail
