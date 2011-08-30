{-# LANGUAGE OverloadedStrings #-}

module Network.DomainAuth.DK.Types where

import Data.ByteString (ByteString)
import qualified Data.Map as M
import Network.DNS
import Network.DomainAuth.Mail

----------------------------------------------------------------

{-|
  Canonicalized key for DomainKey-Signature:.
-}
dkFieldKey :: CanonFieldKey
dkFieldKey = "domainkey-signature"

----------------------------------------------------------------

data DkAlgorithm = DK_RSA_SHA1 deriving (Eq,Show)
data DkCanonAlgo = DK_SIMPLE | DK_NOFWS deriving (Eq,Show)
--data DkQuery = DK_DNS deriving (Eq,Show)
type DkFields = M.Map ByteString Bool -- Key Bool

{-|
  Abstract type for DomainKey-Signature:
-}

data DK = DK {
    dkAlgorithm :: DkAlgorithm
  , dkSignature :: ByteString
  , dkCanonAlgo :: DkCanonAlgo
  , dkDomain0   :: ByteString
  , dkFields    :: Maybe DkFields
--  , dkQuery     :: Maybe DkQuery -- gmail does not provide, sigh
  , dkSelector0 :: ByteString
  } deriving (Eq,Show)

{-|
  Getting of the value of the \"d\" tag in DomainKey-Signature:.
-}
dkDomain :: DK -> Domain
dkDomain = dkDomain0

{-|
  Getting of the value of the \"s\" tag in DomainKey-Signature:.
-}
dkSelector :: DK -> ByteString
dkSelector = dkSelector0
