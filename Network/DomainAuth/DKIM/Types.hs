{-# LANGUAGE OverloadedStrings #-}

module Network.DomainAuth.DKIM.Types where

import qualified Data.ByteString.Lazy.Char8 as L
import Network.DNS
import Network.DomainAuth.Mail

----------------------------------------------------------------

dkimFieldKey :: CanonFieldKey
dkimFieldKey = "dkim-signature"

----------------------------------------------------------------

data DkimSigAlgo = RSA_SHA1 | RSA_SHA256 deriving (Eq,Show)
data DkimCanonAlgo = DKIM_SIMPLE | DKIM_RELAXED deriving (Eq,Show)

data DKIM = DKIM {
    dkimVersion     :: L.ByteString
  , dkimSigAlgo     :: DkimSigAlgo
  , dkimSignature   :: L.ByteString
  , dkimBodyHash    :: L.ByteString
  , dkimHeaderCanon :: DkimCanonAlgo
  , dkimBodyCanon   :: DkimCanonAlgo
  , dkimDomain0     :: L.ByteString
  , dkimFields      :: [CanonFieldKey]
  , dkimLength      :: Maybe Int
  , dkimSelector0   :: L.ByteString
  } deriving (Eq,Show)

dkimDomain :: DKIM -> Domain
dkimDomain = L.unpack . dkimDomain0

dkimSelector :: DKIM -> String
dkimSelector = L.unpack . dkimSelector0
