module Network.DomainAuth.DKIM.Types where

import qualified Data.ByteString.Lazy.Char8 as L

----------------------------------------------------------------

data DkimCanonAlog = DKIM_SIMPLE | DKIM_RELAXED deriving (Eq,Show)
data DkimSigAlgo = RSA_SHA1 | RSA_SHA256 deriving (Eq,Show)

data DKIM = DKIM {
    dkimVersion     :: L.ByteString
  , dkimSigAlgo     :: DkimSigAlgo
  , dkimSignature   :: L.ByteString
  , dkimBodyHash    :: L.ByteString
  , dkimHeaderCanon :: DkimCanonAlog
  , dkimBodyCanon   :: DkimCanonAlog
  , dkimDomain      :: L.ByteString
  , dkimFields      :: [L.ByteString]
  , dkimLength      :: Maybe Int
  , dkimSelector    :: L.ByteString
  }

