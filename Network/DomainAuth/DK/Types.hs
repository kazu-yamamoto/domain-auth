{-# LANGUAGE OverloadedStrings #-}

module Network.DomainAuth.DK.Types where

import qualified Data.ByteString.Lazy.Char8 as L
import qualified Data.Map as M
import Network.DNS
import Network.DomainAuth.Mail

----------------------------------------------------------------

dkFieldKey :: CanonFieldKey
dkFieldKey = "domainkey-signature"

----------------------------------------------------------------

data DkAlgorithm = DK_RSA_SHA1 deriving (Eq,Show)
data DkCanonAlgo = DK_SIMPLE | DK_NOFWS deriving (Eq,Show)
--data DkQuery = DK_DNS deriving (Eq,Show)
type DkFields = M.Map L.ByteString Bool -- Key Bool

{-|
  Abstract type for DomainKey-Signature:
-}

data DK = DK {
    dkAlgorithm :: DkAlgorithm
  , dkSignature :: L.ByteString
  , dkCanonAlgo :: DkCanonAlgo
  , dkDomain0   :: L.ByteString
  , dkFields    :: Maybe DkFields
--  , dkQuery     :: Maybe DkQuery -- gmail does not provide, sigh
  , dkSelector0 :: L.ByteString
  } deriving (Eq,Show)

dkDomain :: DK -> Domain
dkDomain = L.unpack . dkDomain0

dkSelector :: DK -> String
dkSelector = L.unpack . dkSelector0
