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
import Network.DomainAuth.Pubkey.RSAPub
import Network.DomainAuth.Types

runDKIM :: Resolver -> Mail -> IO DAResult
runDKIM resolver mail = dkim1
  where
    dkim1       = maybe (return DANone)      dkim2 $ lookupField dkimFieldKey (mailHeader mail)
    dkim2 dkimv = maybe (return DAPermError) dkim3 $ parseDKIM (toRaw dkimv)
    dkim3       = runDKIM' resolver mail

runDKIM' :: Resolver -> Mail -> DKIM -> IO DAResult
runDKIM' resolver mail dkim = maybe DATempError (verify mail dkim) <$> pub
  where
    pub = lookupPublicKey resolver dom
    dom = dkimSelector dkim ++ "._domainkey." ++ dkimDomain dkim
    verify m d p = if verifyDKIM m d p then DAPass else DAFail
