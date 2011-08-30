{-# LANGUAGE OverloadedStrings #-}

module Network.DomainAuth.DKIM.Types where

import Data.ByteString (ByteString)
import Network.DNS
import Network.DomainAuth.Mail

----------------------------------------------------------------

{-|
  Canonicalized key for DKIM-Signature:.
-}
dkimFieldKey :: CanonFieldKey
dkimFieldKey = "dkim-signature"

----------------------------------------------------------------

data DkimSigAlgo = RSA_SHA1 | RSA_SHA256 deriving (Eq,Show)
data DkimCanonAlgo = DKIM_SIMPLE | DKIM_RELAXED deriving (Eq,Show)

data DKIM = DKIM {
    dkimVersion     :: ByteString
  , dkimSigAlgo     :: DkimSigAlgo
  , dkimSignature   :: ByteString
  , dkimBodyHash    :: ByteString
  , dkimHeaderCanon :: DkimCanonAlgo
  , dkimBodyCanon   :: DkimCanonAlgo
  , dkimDomain0     :: ByteString
  , dkimFields      :: [CanonFieldKey]
  , dkimLength      :: Maybe Int
  , dkimSelector0   :: ByteString
  } deriving (Eq,Show)

{-|
  Getting of the value of the \"d\" tag in DKIM-Signature:.
-}
dkimDomain :: DKIM -> Domain
dkimDomain = dkimDomain0

{-|
  Getting of the value of the \"s\" tag in DKIM-Signature:.
-}
dkimSelector :: DKIM -> ByteString
dkimSelector = dkimSelector0
