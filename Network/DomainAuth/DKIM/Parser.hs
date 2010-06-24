{-# LANGUAGE OverloadedStrings #-}

module Network.DomainAuth.DKIM.Parser where

import Control.Applicative
import qualified Data.ByteString.Lazy.Char8 as L
import Data.Char
import Data.List
import Data.Maybe
import Network.DomainAuth.DKIM.Types
import Network.DomainAuth.Mail
import Prelude hiding (catch)

parseDKIM :: FieldValue -> Maybe DKIM
parseDKIM val = toDKIM domkey
  where
    (ts,vs) = unzip $ parseTaggedValue val
    fs = map tagToSetter ts
    tagToSetter tag = fromMaybe (\_ mdkim -> mdkim) $ lookup (L.unpack tag) dkimTagDB
    pfs = zipWith ($) fs vs
    domkey = foldr ($) initialMDKIM pfs
    toDKIM mdkim = do
        ver <- mdkimVersion     mdkim
        alg <- mdkimSigAlgo     mdkim
        sig <- mdkimSignature   mdkim
        bhs <- mdkimBodyHash    mdkim
        hca <- mdkimHeaderCanon mdkim
        bca <- mdkimBodyCanon   mdkim
        dom <- mdkimDomain      mdkim
        fld <- mdkimFields      mdkim
        sel <- mdkimSelector    mdkim
        return DKIM {
            dkimVersion     = ver
          , dkimSigAlgo     = alg
          , dkimSignature   = sig
          , dkimBodyHash    = bhs
          , dkimHeaderCanon = hca
          , dkimBodyCanon   = bca
          , dkimDomain0     = dom
          , dkimFields      = fld
          , dkimLength      = mdkimLength mdkim
          , dkimSelector0   = sel
          }

data MDKIM = MDKIM {
    mdkimVersion     :: Maybe L.ByteString
  , mdkimSigAlgo     :: Maybe DkimSigAlgo
  , mdkimSignature   :: Maybe L.ByteString
  , mdkimBodyHash    :: Maybe L.ByteString
  , mdkimHeaderCanon :: Maybe DkimCanonAlgo
  , mdkimBodyCanon   :: Maybe DkimCanonAlgo
  , mdkimDomain      :: Maybe L.ByteString
  , mdkimFields      :: Maybe [L.ByteString]
  , mdkimLength      :: Maybe Int
  , mdkimSelector    :: Maybe L.ByteString
  } deriving (Eq,Show)

initialMDKIM :: MDKIM
initialMDKIM = MDKIM {
    mdkimVersion     = Nothing
  , mdkimSigAlgo     = Nothing
  , mdkimSignature   = Nothing
  , mdkimBodyHash    = Nothing
  , mdkimHeaderCanon = Nothing
  , mdkimBodyCanon   = Nothing
  , mdkimDomain      = Nothing
  , mdkimFields      = Nothing
  , mdkimLength      = Nothing
  , mdkimSelector    = Nothing
  }

type DKIMSetter = L.ByteString -> MDKIM -> MDKIM

dkimTagDB :: [(String,DKIMSetter)]
dkimTagDB = [
    ("v",setDkimVersion)
  , ("a",setDkimSigAlgo)
  , ("b",setDkimSignature)
  , ("bh",setDkimBodyHash)
  , ("c",setDkimCanonAlgo)
  , ("d",setDkimDomain)
  , ("h",setDkimFields)
  , ("l",setDkimLength)
  , ("s",setDkimSelector)
  ]

setDkimVersion :: DKIMSetter
setDkimVersion ver dkim = dkim { mdkimVersion = Just ver }

setDkimSigAlgo :: DKIMSetter
setDkimSigAlgo "rsa-sha1" dkim = dkim { mdkimSigAlgo = Just RSA_SHA1 }
setDkimSigAlgo "rsa-sha256" dkim = dkim { mdkimSigAlgo = Just RSA_SHA256 }
setDkimSigAlgo _ _ = error "setDkimSigAlgo"

setDkimSignature :: DKIMSetter
setDkimSignature sig dkim = dkim { mdkimSignature = Just sig }

setDkimBodyHash :: DKIMSetter
setDkimBodyHash bh dkim = dkim { mdkimBodyHash = Just bh }

setDkimCanonAlgo :: DKIMSetter
setDkimCanonAlgo "relaxed" dkim = dkim {
    mdkimHeaderCanon = Just DKIM_RELAXED
  , mdkimBodyCanon   = Just DKIM_SIMPLE
  }
setDkimCanonAlgo "relaxed/relaxed" dkim = dkim {
    mdkimHeaderCanon = Just DKIM_RELAXED
  , mdkimBodyCanon   = Just DKIM_RELAXED
  }
setDkimCanonAlgo "relaxed/simple" dkim = dkim {
    mdkimHeaderCanon = Just DKIM_RELAXED
  , mdkimBodyCanon   = Just DKIM_SIMPLE
  }
setDkimCanonAlgo "simple/relaxed" dkim = dkim {
    mdkimHeaderCanon = Just DKIM_SIMPLE
  , mdkimBodyCanon   = Just DKIM_RELAXED
  }
setDkimCanonAlgo "simple/simple" dkim = dkim {
    mdkimHeaderCanon = Just DKIM_SIMPLE
  , mdkimBodyCanon   = Just DKIM_SIMPLE
  }
setDkimCanonAlgo _ _ = error "setDkimCanonAlgo"

setDkimDomain :: DKIMSetter
setDkimDomain dom dkim = dkim { mdkimDomain = Just dom }

setDkimFields :: DKIMSetter
setDkimFields keys dkim = dkim { mdkimFields = Just (L.split ':' keys) }

setDkimLength :: DKIMSetter
setDkimLength len dkim = dkim { mdkimLength = fst <$> L.readInt len }

setDkimSelector :: DKIMSetter
setDkimSelector sel dkim = dkim { mdkimSelector = Just sel }
