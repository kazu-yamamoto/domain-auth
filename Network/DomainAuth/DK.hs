{-# LANGUAGE OverloadedStrings #-}

-- | A library for DomainKeys (<http://www.ietf.org/rfc/rfc4070>).
--   Currently, only receiver side is implemented.

module Network.DomainAuth.DK (
  -- * Documentation
  -- ** Authentication with DK
    runDK, runDK'
  -- ** Parsing DomainKey-Signature:
  , parseDK
  , DK, dkDomain, dkSelector
  -- ** Field key for DomainKey-Signature:
  , dkFieldKey
  ) where

import Network.DNS as DNS (Resolver)
import Network.DomainAuth.DK.Parser
import Network.DomainAuth.DK.Types
import Network.DomainAuth.DK.Verify
import Network.DomainAuth.Mail
import Network.DomainAuth.Pubkey.RSAPub
import Network.DomainAuth.Types
import qualified Data.ByteString as BS (append)

-- | Verifying 'Mail' with DomainKeys.
runDK :: Resolver -> Mail -> IO DAResult
runDK resolver mail = dk1
  where
    dk1     = maybe (return DANone)      dk2 $ lookupField dkFieldKey (mailHeader mail)
    dk2 dkv = maybe (return DAPermError) dk3 $ parseDK (fieldValueUnfolded dkv)
    dk3     = runDK' resolver mail

-- | Verifying 'Mail' with DomainKeys. The value of DomainKey-Signature:
--   should be parsed beforehand.
runDK' :: Resolver -> Mail -> DK -> IO DAResult
runDK' resolver mail dk = maybe DATempError (verify mail dk) <$> pub
  where
    pub = lookupPublicKey resolver dom
    dom = dkSelector dk +++ "._domainkey." +++ dkDomain dk
    verify m d p = if verifyDK m d p then DAPass else DAFail
    (+++) = BS.append
