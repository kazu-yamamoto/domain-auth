{-# LANGUAGE OverloadedStrings #-}

module Network.DomainAuth.DK.Parser where

import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as BS
import Data.List
import qualified Data.Map as M
import Data.Maybe
import Network.DomainAuth.DK.Types
import Network.DomainAuth.Mail

{-|
  Parsing DomainKey-Signature:.
-}
parseDK :: RawFieldValue -> Maybe DK
parseDK val = toDK domkey
  where
    (ts,vs) = unzip $ parseTaggedValue val
    fs = map tagToSetter ts
    tagToSetter tag = fromMaybe (\_ mdk -> mdk) $ lookup (BS.head tag) dkTagDB
    pfs = zipWith ($) fs vs
    domkey = foldr ($) initialMDK pfs
    toDK mdk = do
        alg <- mdkAlgorithm mdk
        sig <- mdkSignature mdk
        cal <- mdkCanonAlgo mdk
        dom <- mdkDomain    mdk
        sel <- mdkSelector  mdk
        return DK {
            dkAlgorithm = alg
          , dkSignature = sig
          , dkCanonAlgo = cal
          , dkDomain0   = dom
          , dkFields    = mdkFields mdk
          , dkSelector0 = sel
          }

data MDK = MDK {
    mdkAlgorithm :: Maybe DkAlgorithm
  , mdkSignature :: Maybe ByteString
  , mdkCanonAlgo :: Maybe DkCanonAlgo
  , mdkDomain    :: Maybe ByteString
  , mdkFields    :: Maybe DkFields
  , mdkSelector  :: Maybe ByteString
  } deriving (Eq,Show)

initialMDK :: MDK
initialMDK = MDK {
    mdkAlgorithm = Just DK_RSA_SHA1
  , mdkSignature = Nothing
  , mdkCanonAlgo = Nothing
  , mdkDomain    = Nothing
  , mdkFields    = Nothing
  , mdkSelector  = Nothing
  }

type DKSetter = ByteString -> MDK -> MDK

dkTagDB :: [(Char,DKSetter)]
dkTagDB = [
    ('a',setDkAlgorithm)
  , ('b',setDkSignature)
  , ('c',setDkCanonAlgo)
  , ('d',setDkDomain)
  , ('h',setDkFields)
--  , ('q',setDkQuery)
  , ('s',setDkSelector)
  ]

setDkAlgorithm :: DKSetter
setDkAlgorithm "rsa-sha1" dk = dk { mdkAlgorithm = Just DK_RSA_SHA1 }
setDkAlgorithm _ _           = error "setDkAlgorithm"

setDkSignature :: DKSetter
setDkSignature sig dk = dk { mdkSignature = Just sig }

setDkCanonAlgo :: DKSetter
setDkCanonAlgo "simple" dk = dk { mdkCanonAlgo = Just DK_SIMPLE }
setDkCanonAlgo "nofws"  dk = dk { mdkCanonAlgo = Just DK_NOFWS }
setDkCanonAlgo  _ _        = error "setDkCanonAlgo"

setDkDomain :: DKSetter
setDkDomain dom dk = dk { mdkDomain = Just dom }

setDkFields :: DKSetter
setDkFields keys dk = dk { mdkFields = Just mx }
  where
    flds = BS.split ':' keys
    mx = foldl' func M.empty flds
    func m fld = M.insert fld True m

{-
setDkQuery :: DKSetter
setDkQuery "dns" dk = dk { mdkQuery = Just DK_DNS }
setDkQuery _ _      = error "setDkQuery"
-}

setDkSelector :: DKSetter
setDkSelector sel dk = dk { mdkSelector = Just sel }
